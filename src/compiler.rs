use std::{any, error::Error, rc::Rc};

use anyhow::{anyhow, Ok, Result};

use crate::parser;

pub struct CompiledProgram {
  pub text: Vec<u8>,
  pub data: Vec<u8>,
  pub entrypoint: u64,
}

pub fn compile(parsed: pest::iterators::Pairs<'_, parser::Rule>) -> Result<CompiledProgram> {
  // Collect global symbol information (functions and values)

  // Initialize the data section from globals

  // Build the text section from the functions

  let mut text = Vec::new();
  let mut data = Vec::new();

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

        if return_type.as_str() != "uint64" {
          return Err(anyhow!("the main function must return uint64"));
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

            // TODO: To handle this properlywe want a list of syscalls, prevent those from being
            // used as function names, and then check function calls agains the global symbol
            // table and the syscall table.
            if function_name != "exit" {
              // exit is the only supported function right now, it's a syscall
              return Err(anyhow!("Only the exit syscall is supported right now"));
            }

            // exit syscall implementation. This needs to be moved into a proper place later on.
            // preferably a function that takes the global and local symbol tables and the
            // function args.
            if function_arguments.len() != 1 {
              return Err(anyhow!("The exit function takes exactly one argument"));
            }

            let first_arg = function_arguments[0].clone().into_inner().next().unwrap();
            if first_arg.as_rule() != parser::Rule::integer_literal {
              return Err(anyhow!(
                "The exit function currently only supports integer literals, but got a {:?}",
                first_arg.as_rule()
              ));
            }

            let ret_code: u64 = first_arg.as_str().parse()?; 

            // TODO: this should be a helper function as in mov_immediate(Register::rax, Syscalls::Exit);
            // move rax
            text.push(0xb8);
            text.push(Syscalls::Exit as u8);
            text.push(0);
            text.push(0);
            text.push(0);

            // mov edi
            text.push(0xbf);
            text.push((ret_code & 0xFF) as u8);
            text.push(((ret_code >> 8) & 0xFF) as u8);
            text.push(((ret_code >> 16) & 0xFF) as u8);
            text.push(((ret_code >> 24) & 0xFF) as u8);

            // syscall
            // TODO: this should also be a helper
            text.push(0x0f);
            text.push(0x05);

            
          }
          _ => {
            return Err(anyhow!(
              "Statements of typpe {:?} are not supported yet",
              typed_expression.as_rule()
            ))
          }
        }
      }
    }
  }
  // let text = vec![
  //   // TODO: This is 0xb8 + the regsite something. Might be based upon the Adressing Forms table in the
  //   // intel manual.
  //   0xb8, // move eax (For using rax we'd need a rex prefix)
  //   60, // 60
  //   0,
  //   0,
  //   0,
  //   0xbf, // mov edi
  //   42, // 42
  //   0,
  //   0,
  //   0,
  //   0x0f, // syscall (0f 05)
  //   0x05
  // ];

  // let data = vec![b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', b'!'];

  Ok(CompiledProgram {
    text,
    data,
    entrypoint: 0,
  })
}

fn collect_smbols() -> Result<()> {
  Ok(())
}

// Syscalls
// TODO: These should be 64 bits
#[repr(u32)]
enum Syscalls {
  Exit = 60,
}
