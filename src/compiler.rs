use std::{any, collections::HashMap, error::Error, rc::Rc};

use anyhow::{anyhow, Context, Ok, Result};

use crate::{elf::ElfFile, parser};

pub struct CompiledProgram {
  pub text: Vec<u8>,
  pub data: Vec<u8>,
  pub entrypoint: u64,
}

#[derive(Default)]
pub struct Compiler {
  // The compiled program code
  text: Vec<u8>,
  // The compiled data section
  data: Vec<u8>,
  symbols: HashMap<String, Symbol>,
  local_symbols: HashMap<String, LocalSymbol>,

  functions: HashMap<String, FunctionSymbol>,

  relative_data_locations: Vec<RelativeDataLocation>,
  relative_call_locations: Vec<RelativeCallLocation>,
}

enum Symbol {
  // TODO: These are missing data
  Function(FunctionSymbol),
  Global(GlobalSymbol),
}

struct GlobalSymbol {
  // The relative address of the global in the data section (relative to the start of the section)
  relative_address: Option<u64>,
}

struct FunctionSymbol {
  // The address of a function relative to the start of the text section.
  // May be None if the function is known, but not yet compiled
  relative_address: Option<u64>,
  // Function argument types. Their names aren't important.
  arguments: Vec<BrokkrType>,
  // The return type of the function.
  return_type: BrokkrType,
}

/// LocalSymbol represents a symbol in the local context, by combining it with a bracket depth.
struct LocalSymbol {
  symbol: Symbol,
  // The depth in braces of this symbol. Used to keep symbols inside of e.g. if clauses.
  depth: u64,
}

// representation for Immediate values. DataAddr are understood to be relative to the start of the
// data section
enum Immediate64 {
  Val(u64),
  DataAddr(u64),
}

/// RelativeDataLocation describes an address in the data section of the compiled code. These need
/// to be stored during compilation, and then updated once the location of the data section is
/// known.
struct RelativeDataLocation {
  // The offset in the text section at which the value lies
  offset: u64,
  // The value's size
  size_bytes: u8,
  // The relative location to which the start of the data section has to be added
  relative_location: u64,
}

// FunctionAddressLocation describe a function address. These need to be stored during compilation,
// and then updated afterwards, once all function locations are known.
struct RelativeCallLocation {
  offset: u64,
  size_bytes: u8,
  function_name: String,
}

impl Compiler {
  pub fn compile(
    mut self,
    parsed: pest::iterators::Pairs<'_, parser::Rule>,
  ) -> Result<CompiledProgram> {
    // Collect global symbol information (functions and values)
    // this populates self.symbols
    self.collect_symbols(parsed.clone())?;

    // Initialize the data section from globals

    // Build the text section from the functions
    // The entry point of our program. It will point at the location of the main function.
    let mut entrypoint = 0;

    for value in parsed {
      if value.as_rule() == parser::Rule::function {
        let mut function_parts = value.into_inner();
        if function_parts.len() != 2 {
          return Err(anyhow!(
            "Expectd two parts in a function, got {}",
            function_parts.len()
          ));
        }

        let signature = FunctionSignature::try_from(function_parts.next().unwrap())?;
        let body = function_parts.next().unwrap().into_inner();

        if signature.name == "main" {
          // sanity checks
          if !signature.arguments.is_empty() {
            return Err(anyhow!("the main function may not take any arguments"));
          }

          if signature.return_type != BrokkrType::UInt64 {
            return Err(anyhow!(
              "the main function must return {}",
              type_to_string(BrokkrType::UInt64)
            ));
          }

          // This is now the entry point
          entrypoint = self.text.len() as u64;
        } else {
          // Update the function table with the location of this function
          match self.functions.get_mut(&signature.name) {
            Some(f) => {f.relative_address = Some(self.text.len() as u64);}
            None => {return Err(anyhow!("Ran into a function signature that was not in the function symbol table during compilation: {}", signature.name))}
          }
        }

        // compile the function
        self.compile_function(body)?;

        if signature.name == "main" {
          // We should make sure the program will exit gracefully
          self.write_syscall_exit_ok();
        } else {
          // The function must return. This allows for writing void functions without a
          // return statement.
          self.write_ret_near();
        }
      }
    }

    // iterate the relative_data_locations and calculate their in memory locations using the
    // ALIGNMENT from elf.rs as well as the KERNEL_MIN_LOAD_ADDRESS.
    let data_start = ElfFile::get_aligned_data_offset(self.text.len() as u64);
    for rewrite in self.relative_data_locations {
      if rewrite.size_bytes == 4 {
        Self::write_u32_at(
          data_start as u32 + rewrite.relative_location as u32,
          &mut self.text[..],
          rewrite.offset as usize,
        );
      } else if rewrite.size_bytes == 8 {
        Self::write_u64_at(
          data_start + rewrite.relative_location,
          &mut self.text[..],
          rewrite.offset as usize,
        );
      } else {
        return Err(anyhow!(
          "got a data address rewrite with an unsupported size of {}",
          rewrite.size_bytes
        ));
      }
    }

    // Rewrite function address locations
    for rewrite in self.relative_call_locations {
      let function = match self.functions.get(&rewrite.function_name) {
        Some(f) => f,
        None => {
          return Err(anyhow!(
            "Got a function address rewrite for unknown function {}",
            rewrite.function_name
          ));
        }
      };

      let function_addr = match function.relative_address {
        Some(a) => a,
        None => {
          return Err(anyhow!(
            "Tried to rewrite address of function {} but it doesn't have an address set",
            rewrite.function_name
          ));
        }
      };

      // The jump is relative to the start of the next instruction, which is why 4 bytes are added
      // for the 4 byte argument to the near jump.
      let offset: i32 = (function_addr as i32) - ((rewrite.offset as i32) + 4);

      // Near jump's in 64 bit mode expect 32bit arguments.
      if rewrite.size_bytes == 4 {
        Self::write_i32_at(offset, &mut self.text[..], rewrite.offset as usize);
      } else {
        return Err(anyhow!(
          "got a function address rewrite with an unsupported size of {}",
          rewrite.size_bytes
        ));
      }
    }

    Ok(CompiledProgram {
      text: self.text,
      data: self.data,
      entrypoint,
    })
  }

  /// compile_function takes a function body and turns it into machine code, appending it to text
  /// at the end of the current text section.
  fn compile_function(&mut self, body: pest::iterators::Pairs<'_, parser::Rule>) -> Result<()> {
    // TODO: we want a local function table that tracks scoped variables.

    for expression in body {
      let typed_expression = expression.into_inner().next().unwrap();

      match typed_expression.as_rule() {
        parser::Rule::call_expression => {
          let call_parts: Vec<_> = typed_expression.into_inner().collect();

          // <name> <args> <terminator>
          if call_parts.len() != 3 {
            return Err(anyhow!(
              "Assigning the result of a function to a variable is not yet supported"
            ));
          }

          let function_name = call_parts[0].as_str().to_string();
          let function_arguments: Vec<_> = call_parts[1].clone().into_inner().collect();

          let function = self.functions.get(&function_name);

          if let Some(_f) = function {
            // There is a function in the global symbol table.
            // TODO: push the function arguments onto the stack
            self.write_call_near(function_name.clone());
          } else {
            // TODO: To handle this properly we want a list of syscalls, prevent those from being
            // used as function names, and then check function calls agains the global symbol
            // table and the syscall table.
            if function_name == "exit" {
              self.write_syscall_exit(function_arguments)?;
            } else if function_name == "print" {
              self.write_syscall_print(function_arguments)?;
            } else {
              // TODO: handle user defined functions
              return Err(anyhow!(
                "Only the exit and print built-ins are supported right now"
              ));
            }
          }
        }
        _ => {
          return Err(anyhow!(
            "Statements of type {:?} are not supported yet",
            typed_expression.as_rule()
          ))
        }
      }
    }
    Ok(())
  }

  fn collect_symbols(&mut self, parsed: pest::iterators::Pairs<'_, parser::Rule>) -> Result<()> {
    for value in parsed {
      match value.as_rule() {
        parser::Rule::function => {
          let v = value.into_inner().next().unwrap();

          let signature = FunctionSignature::try_from(v)?;

          // TODO: check the signature against the list of built-ins and error if there is a
          // built-in with the same name.

          self.functions.insert(
            signature.name,
            FunctionSymbol {
              relative_address: None,
              arguments: signature.arguments,
              return_type: signature.return_type,
            },
          );
        }
        parser::Rule::global_definition => {
          panic!("globals are not yet supported");
        }
        parser::Rule::EOI => {}
        _ => {
          return Err(anyhow!(
            "Expected only functions and globals at the global scope, got '{}'",
            value.as_str()
          ));
        }
      }
    }
    Ok(())
  }

  // syscalls
  fn write_syscall_exit(
    &mut self,
    arguments: Vec<pest::iterators::Pair<'_, parser::Rule>>,
  ) -> Result<()> {
    if arguments.len() != 1 {
      return Err(anyhow!("The exit function takes exactly one argument"));
    }

    let first_arg = arguments[0].clone().into_inner().next().unwrap();
    if first_arg.as_rule() != parser::Rule::integer_literal {
      return Err(anyhow!(
        "The exit function currently only supports integer literals, but got a {:?}",
        first_arg.as_rule()
      ));
    }

    let ret_code: u64 = first_arg.as_str().parse()?;

    // call the exit syscall with a single return code argument
    self.write_mov_immediate_64(Register64::Rax, Immediate64::Val(Syscalls::Exit as u64));
    self.write_mov_immediate_64(Register64::Rdi, Immediate64::Val(ret_code));
    self.write_syscall();

    Ok(())
  }

  fn write_syscall_exit_ok(&mut self) {
    // call the exit syscall with a single return code argument
    self.write_mov_immediate_64(Register64::Rax, Immediate64::Val(Syscalls::Exit as u64));
    self.write_mov_immediate_64(Register64::Rdi, Immediate64::Val(0));
    self.write_syscall();
  }

  // TODO: The syscall is write, print should just be a wrapper around that.
  fn write_syscall_print(
    &mut self,
    arguments: Vec<pest::iterators::Pair<'_, parser::Rule>>,
  ) -> Result<()> {
    if arguments.len() != 2 && arguments.len() != 1 {
      return Err(anyhow!("The print function takes exactly two arguments"));
    }

    let first_arg = arguments[0].clone().into_inner().next().unwrap();
    if first_arg.as_rule() != parser::Rule::string_literal {
      return Err(anyhow!(
        "The print function currently only supports string literals, but got a {:?}",
        first_arg.as_rule()
      ));
    }

    // The second arg is only used for the variable version of this
    // let second_arg = arguments[1].clone().into_inner().next().unwrap();
    // if second_arg.as_rule() != parser::Rule::integer_literal {
    //   return Err(anyhow!(
    //     "The print function currently only supports integer literals, but got a {:?}",
    //     first_arg.as_rule()
    //   ));
    // }

    // the literal is surrounded by qutation marks
    let string_literal = first_arg.as_str()[1..first_arg.as_str().len() - 1].to_string();
    // let string_length: u64 = second_arg.as_str().parse()?;
    let string_length = string_literal.len() as u64;

    // add the string literal to the data section
    let relative_literal_location = self.data_add_string(&string_literal);

    // call the exit syscall with a single return code argument
    self.write_mov_immediate_64(Register64::Rax, Immediate64::Val(Syscalls::Write as u64));
    self.write_mov_immediate_64(Register64::Rdi, Immediate64::Val(FD_STDOUT));

    // We refer to the literal in the data section here and need to modify this later on to hold
    // the actual location of the data.
    self.write_mov_immediate_64(
      Register64::Rsi,
      Immediate64::DataAddr(relative_literal_location),
    );
    self.write_mov_immediate_64(Register64::Rdx, Immediate64::Val(string_length));
    self.write_syscall();

    Ok(())
  }

  fn write_syscall_write(&mut self, arguments: Vec<pest::iterators::Pair<'_, parser::Rule>>) {}

  // helper functions

  fn write_call_near(&mut self, target: String) {
    // The relative near call opcode
    self.text.push(0xe8);

    // We are running in 64-bit mode, so the operand is always 32bits
    self.relative_call_locations.push(RelativeCallLocation {
      offset: self.text.len() as u64,
      size_bytes: 4,
      function_name: target,
    });

    Self::write_u32(0, &mut self.text);
  }

  fn write_ret_near(&mut self) {
    // The far call opcode
    self.text.push(0xc3);
  }

  /// write_mov_immediate_32 writes a mov instruction moving an immediate value (e.g. integer) into
  /// the given register. The instructions are written into target.
  fn write_mov_immediate_32(register: Register32, val: u32, target: &mut Vec<u8>) {
    target.push(0xb8 + register as u8);
    Self::write_u32(val, target);
  }

  /// write_mov_immediate_64 writes a mov instruction moving an immediate value (e.g. integer) into
  /// the given register. The instructions are written into target.
  fn write_mov_immediate_64(&mut self, register: Register64, val: Immediate64) {
    self.text.push(REXPrefix::Mode64Bit as u8);
    self.text.push(0xb8 + register as u8);
    match val {
      Immediate64::Val(v) => Self::write_u64(v, &mut self.text),
      Immediate64::DataAddr(a) => {
        self.relative_data_locations.push(RelativeDataLocation {
          // the mov instruction takes 2 bytes.
          offset: self.text.len() as u64,
          size_bytes: 8,
          relative_location: a,
        });
        Self::write_u64(a, &mut self.text);
      }
    }
  }

  /// write_syscall writes a syscall opcode to the text section. It uses the 64bit syscall
  /// instruction, not the old interrupt 80.
  fn write_syscall(&mut self) {
    self.text.push(0x0f);
    self.text.push(0x05);
  }

  /// Writes a little endian two's complement i32 to the vector
  fn write_i32_at(data: i32, target: &mut [u8], offset: usize) {
    unsafe {
      let v = std::mem::transmute::<i32, u32>(data);

      target[offset] = (v & 0xFF) as u8;
      target[offset + 1] = ((v >> 8) & 0xFF) as u8;
      target[offset + 2] = ((v >> 16) & 0xFF) as u8;
      target[offset + 3] = ((v >> 24) & 0xFF) as u8;
    }
  }

  fn write_i32(data: i32, target: &mut Vec<u8>) {
    unsafe {
      let v = std::mem::transmute::<i32, u32>(data);
      target.push((v & 0xFF) as u8);
      target.push(((v >> 8) & 0xFF) as u8);
      target.push(((v >> 16) & 0xFF) as u8);
      target.push(((v >> 24) & 0xFF) as u8);
    }
  }

  /// Writes a little endian u32 to the vector
  fn write_u32(data: u32, target: &mut Vec<u8>) {
    target.push((data & 0xFF) as u8);
    target.push(((data >> 8) & 0xFF) as u8);
    target.push(((data >> 16) & 0xFF) as u8);
    target.push(((data >> 24) & 0xFF) as u8);
  }

  /// Writes a little endian u64 to the vector
  fn write_u64(data: u64, target: &mut Vec<u8>) {
    target.push((data & 0xFF) as u8);
    target.push(((data >> 8) & 0xFF) as u8);
    target.push(((data >> 16) & 0xFF) as u8);
    target.push(((data >> 24) & 0xFF) as u8);
    target.push(((data >> 32) & 0xFF) as u8);
    target.push(((data >> 40) & 0xFF) as u8);
    target.push(((data >> 48) & 0xFF) as u8);
    target.push(((data >> 56) & 0xFF) as u8);
  }

  /// Writes a little endian u32 to the vector
  fn write_u32_at(data: u32, target: &mut [u8], offset: usize) {
    target[offset] = (data & 0xFF) as u8;
    target[offset + 1] = ((data >> 8) & 0xFF) as u8;
    target[offset + 2] = ((data >> 16) & 0xFF) as u8;
    target[offset + 3] = ((data >> 24) & 0xFF) as u8;
  }

  /// Writes a little endian u64 to the vector
  fn write_u64_at(data: u64, target: &mut [u8], offset: usize) {
    target[offset] = (data & 0xFF) as u8;
    target[offset + 1] = ((data >> 8) & 0xFF) as u8;
    target[offset + 2] = ((data >> 16) & 0xFF) as u8;
    target[offset + 3] = ((data >> 24) & 0xFF) as u8;
    target[offset + 4] = ((data >> 32) & 0xFF) as u8;
    target[offset + 5] = ((data >> 40) & 0xFF) as u8;
    target[offset + 6] = ((data >> 48) & 0xFF) as u8;
    target[offset + 7] = ((data >> 56) & 0xFF) as u8;
  }

  /// data_add_string adds the string to the data section and returns its relative address
  fn data_add_string(&mut self, val: &str) -> u64 {
    let addr = self.data.len();
    self.data.extend_from_slice(val.as_bytes());

    addr as u64
  }
}

/// Holds a function's signature. Function signatures need to be parsed in several places, this is
/// used to be able to write a parsing function for them.
struct FunctionSignature {
  name: String,
  return_type: BrokkrType,
  arguments: Vec<BrokkrType>,
}

impl TryFrom<pest::iterators::Pair<'_, parser::Rule>> for FunctionSignature {
  type Error = anyhow::Error;

  fn try_from(
    value: pest::iterators::Pair<'_, parser::Rule>,
  ) -> std::result::Result<Self, Self::Error> {
    if value.as_rule() != parser::Rule::function_signature {
      return Err(anyhow!(
        "unable to parse non-function-signature as function signature."
      ));
    }

    let parts: Vec<_> = value.clone().into_inner().collect();

    let return_type = BrokkrType::try_from(parts[0].clone())
      .with_context(|| format!("Unable to parse function signature type {}", value.as_str()))?;

    let name = parts[1].as_str().to_string();

    let mut args = Vec::new();
    let mut arg_iter = parts[2].clone().into_inner();
    loop {
      let arg_type = BrokkrType::try_from(match arg_iter.next() {
        Some(v) => v,
        None => break,
      })
      .with_context(|| format!("Unable to parse function argument in {}", parts[2].as_str()))?;
      args.push(arg_type);

      // consume the name and a comma
      arg_iter.next();
      arg_iter.next();
    }

    Ok(FunctionSignature {
      name,
      return_type,
      arguments: args,
    })
  }
}

// Syscalls
// TODO: These should be 64 bits
#[repr(u64)]
enum Syscalls {
  Write = 1,
  Exit = 60,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BrokkrType {
  Void,
  UInt64,
  Double,
  Uint8tPtr,
}

impl TryFrom<pest::iterators::Pair<'_, parser::Rule>> for BrokkrType {
  type Error = anyhow::Error;

  fn try_from(
    value: pest::iterators::Pair<'_, parser::Rule>,
  ) -> std::result::Result<Self, Self::Error> {
    if value.as_rule() != parser::Rule::types {
      return Err(anyhow!("unable to parse non brokkr-type as brokkr type."));
    }

    let text = value.as_str();

    match text {
      "void" => Ok(BrokkrType::Void),
      "uint64" => Ok(BrokkrType::UInt64),
      "double" => Ok(BrokkrType::Double),
      "uint8*" => Ok(BrokkrType::Uint8tPtr),
      _ => Err(anyhow!("{} is not a valid brokrr type", text)),
    }
  }
}

const fn type_to_string(t: BrokkrType) -> &'static str {
  match t {
    BrokkrType::Void => "void",
    BrokkrType::UInt64 => "uint64",
    BrokkrType::Double => "double",
    BrokkrType::Uint8tPtr => "uint8*",
  }
}

#[repr(u64)]
enum Register32 {
  Eax = 0,
  Ecx = 1,
  Edx = 2,
  Ebx = 3,
  Esi = 6,
  Edi = 7,
}

#[repr(u64)]
enum Register64 {
  Rax = 0,
  Rcx = 1,
  Rdx = 2,
  Rbx = 3,
  Rsi = 6,
  Rdi = 7,
}

#[repr(u8)]
enum REXPrefix {
  // Enable 64 bit mode for the next opcode. Must immediately proceed the opcode
  Mode64Bit = 0b01001000,
}

const FD_STDOUT: u64 = 1;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_write_u32() {
    let v = 0b0110010110011101101110001010110;
    let mut target = Vec::new();

    Compiler::write_u32(v, &mut target);
    assert_eq!(target[0], 0b01010110);
    assert_eq!(target[1], 0b11011100);
    assert_eq!(target[2], 0b11001110);
    assert_eq!(target[3], 0b00110010);
  }

  #[test]
  fn test_write_i32() {
    let v = -0b1110010110011101101110001010110;
    let mut target = Vec::new();

    println!("v: {}", v);
    println!("v & 0xFF: {}", v & 0xFF);

    // These bits are the  binary number, that fulfills -(1 << 32) + x = 0b1110010110011101101110001010110
    Compiler::write_i32(v, &mut target);
    assert_eq!(target[0], 0b10101010);
    assert_eq!(target[1], 0b00100011);
    assert_eq!(target[2], 0b00110001);
    assert_eq!(target[3], 0b10001101);

    target.push(0);
    target.push(0);
    target.push(0);
    target.push(0);
    Compiler::write_i32_at(v, &mut target[..], 4);
    assert_eq!(target[4], 0b10101010);
    assert_eq!(target[5], 0b00100011);
    assert_eq!(target[6], 0b00110001);
    assert_eq!(target[7], 0b10001101);
  }
}
