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
    // TODO: This is 0xb8 + the regsite something. Might be based upon the Adressing Forms table in the
    // intel manual.
    0xb8, // move eax (For using rax we'd need a rex prefix)
    60, // 60
    0,
    0,
    0,
    0xbf, // mov edi
    42, // 42
    0,
    0,
    0,
    0x0f, // syscall (0f 05)
    0x05
  ];
  
  let data = vec![b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', b'!'];

  Ok(CompiledProgram { text, data, entrypoint: 0 })
}

fn collect_smbols() -> Result<()> {

  Ok(())
}

