use anyhow::{Result, Ok};

use crate::parser;


pub struct CompiledProgram {
  pub text: Vec<u8>,
  pub data: Vec<u8>,
  pub entrypoint: u64,
}

pub fn compile(parsed: pest::iterators::Pairs<'_, parser::Rule>) -> Result<CompiledProgram> {

  // Collect global symbol information (functions and values)

  // Build the data section from globals

  // Build the text section from the functions
  let text = vec![
    0xb8, // move eax
    60, // 60
    0,
    0,
    0,
    0xbf, // mov edi
    42, // 42
    0,
    0,
    0,
    0x0f, // syscall
    0x05
  ];
  // TODO: Find the bytecode for the following instructions
  // mov rax, 60
  // mov rdi, 42
  // syscall
  
  let data = vec![b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', b'!'];

  Ok(CompiledProgram { text, data, entrypoint: 0 })
}

fn collect_smbols() -> Result<()> {

  Ok(())
}

