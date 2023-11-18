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
  let text = vec![];
  // TODO: Find the bytecode for the following instructions
  // mov rax, 60
  // xor rdi, rdi
  // syscall

  Ok(CompiledProgram { text, data: Vec::new(), entrypoint: 0 })
}

fn collect_smbols() -> Result<()> {

  Ok(())
}

