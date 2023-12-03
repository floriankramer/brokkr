use std::{any, collections::HashMap, error::Error, rc::Rc};

use anyhow::{anyhow, Ok, Result};

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

  relative_data_locations: Vec<RelativeDataLocation>,
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

impl Compiler {
  pub fn compile(
    mut self,
    parsed: pest::iterators::Pairs<'_, parser::Rule>,
  ) -> Result<CompiledProgram> {
    // Collect global symbol information (functions and values)
    // this populates self.symbols
    self.collect_smbols()?;

    // Initialize the data section from globals

    // Build the text section from the functions

    // For now, we only look at the main function
    for value in parsed {
      if value.as_rule() == parser::Rule::function {
        let mut function_parts = value.into_inner();
        if function_parts.len() != 2 {
          return Err(anyhow!(
            "Expectd two parts in a function, got {}",
            function_parts.len()
          ));
        }

        let signature = function_parts.next().unwrap();
        let mut body = function_parts.next().unwrap().into_inner();

        let mut signature_parts = signature.into_inner();
        let return_type = signature_parts.next().unwrap();
        let function_name = signature_parts.next().unwrap().as_str().to_string();

        let mut function_arguments = signature_parts.next().unwrap().into_inner();

        // Debug code
        if function_name != "main" {
          log::info!("Ignoring non main function {} in this build", function_name);
          continue;
        }

        if function_name == "main" {
          // sanity checks
          if function_arguments.clone().next().is_some() {
            return Err(anyhow!("the main function may not take any arguments"));
          }

          if return_type.as_str() != type_to_string(BrokkrType::UInt64) {
            return Err(anyhow!(
              "the main function must return {}",
              type_to_string(BrokkrType::UInt64)
            ));
          }
        }

        // compile the function
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

              // TODO: To handle this properly we want a list of syscalls, prevent those from being
              // used as function names, and then check function calls agains the global symbol
              // table and the syscall table.
              // TODO: Add the print function to this.
              if function_name == "exit" {
                self.write_syscall_exit(function_arguments)?;
              } else if function_name == "print" {
                self.write_syscall_print(function_arguments)?;
              } else {
                return Err(anyhow!("Only the exit and print are supported right now"));
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

        if function_name == "main" {
          // We should make sure the program will exit gracefully
          self.write_syscall_exit_ok();
        }
      }
    }

    // TODO: Adjust relative data locations
    // iterate the relative_data_locations and calculate their in memory locations using the
    // ALIGNMENT from elf.rs as well as the KERNEL_MIN_LOAD_ADDRESS. There should probably be a
    // helper inside of elf.rs for this. It's not the cleanest separation of concerns, but should
    // be fine for this basic compiler project.
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
          "got a rewrite with an unsupported size of {}",
          rewrite.size_bytes
        ));
      }
    }

    Ok(CompiledProgram {
      text: self.text,
      data: self.data,
      entrypoint: 0,
    })
  }

  fn collect_smbols(&mut self) -> Result<()> {
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
    Self::write_mov_immediate_64(Register64::Rax, Syscalls::Exit as u64, &mut self.text);
    Self::write_mov_immediate_64(Register64::Rdi, ret_code, &mut self.text);
    Self::write_syscall(&mut self.text);

    Ok(())
  }

  fn write_syscall_exit_ok(&mut self) {
    // call the exit syscall with a single return code argument
    Self::write_mov_immediate_64(Register64::Rax, Syscalls::Exit as u64, &mut self.text);
    Self::write_mov_immediate_64(Register64::Rdi, 0, &mut self.text);
    Self::write_syscall(&mut self.text);
  }

  // TODO: The syscall is write, print should just be a wrapper around that.
  fn write_syscall_print(
    &mut self,
    arguments: Vec<pest::iterators::Pair<'_, parser::Rule>>,
  ) -> Result<()> {
    if arguments.len() != 2 {
      return Err(anyhow!("The print function takes exactly two arguments"));
    }

    let first_arg = arguments[0].clone().into_inner().next().unwrap();
    if first_arg.as_rule() != parser::Rule::string_literal {
      return Err(anyhow!(
        "The print function currently only supports string literals, but got a {:?}",
        first_arg.as_rule()
      ));
    }

    let second_arg = arguments[1].clone().into_inner().next().unwrap();
    if second_arg.as_rule() != parser::Rule::integer_literal {
      return Err(anyhow!(
        "The print function currently only supports integer literals, but got a {:?}",
        first_arg.as_rule()
      ));
    }

    // the literal is surrounded by qutation marks
    let string_literal = first_arg.as_str()[1..first_arg.as_str().len() - 1].to_string();
    let string_length: u64 = second_arg.as_str().parse()?;

    // add the string literal to the data section
    let relative_literal_location = self.data.len() as u64;
    self.data.extend_from_slice(string_literal.as_bytes());

    // call the exit syscall with a single return code argument
    Self::write_mov_immediate_64(Register64::Rax, Syscalls::Write as u64, &mut self.text);
    Self::write_mov_immediate_64(Register64::Rdi, 1, &mut self.text);

    // We refer to the literal in the data section here and need to modify this later on to hold
    // the actual location of the data.
    self.relative_data_locations.push(RelativeDataLocation {
      // the mov instruction takes 2 bytes.
      offset: self.text.len() as u64 + 2,
      size_bytes: 8,
      relative_location: relative_literal_location,
    });
    Self::write_mov_immediate_64(Register64::Rsi, relative_literal_location, &mut self.text);
    Self::write_mov_immediate_64(Register64::Rdx, string_length, &mut self.text);
    Self::write_syscall(&mut self.text);

    Ok(())
  }

  // helper functions

  /// write_mov_immediate_32 writes a mov instruction moving an immediate value (e.g. integer) into
  /// the given register. The instructions are written into target.
  fn write_mov_immediate_32(register: Register32, val: u32, target: &mut Vec<u8>) {
    target.push(0xb8 + register as u8);
    Self::write_u32(val, target);
  }

  /// write_mov_immediate_64 writes a mov instruction moving an immediate value (e.g. integer) into
  /// the given register. The instructions are written into target.
  fn write_mov_immediate_64(register: Register64, val: u64, target: &mut Vec<u8>) {
    target.push(REXPrefix::Mode64Bit as u8);
    target.push(0xb8 + register as u8);
    Self::write_u64(val, target);
  }

  /// write_syscall writes a syscall opcode to the target vector. It uses the 64bit syscall
  /// instruction, not the old interrupt 80.
  fn write_syscall(target: &mut Vec<u8>) {
    target.push(0x0f);
    target.push(0x05);
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
}

// Syscalls
// TODO: These should be 64 bits
#[repr(u64)]
enum Syscalls {
  Write = 1,
  Exit = 60,
}

enum BrokkrType {
  Void,
  UInt64,
  Double,
  Uint8tPtr,
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
