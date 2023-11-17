use anyhow::{Result, Ok};

use crate::parser;


pub struct CompiledProgram {
  pub text: Vec<u8>,
  pub data: Vec<u8>,
}

pub fn compile(parsed: pest::iterators::Pairs<'_, parser::Rule>) -> Result<CompiledProgram> {

  // Collect global symbol information (functions and values)

  // Build the data section from globals

  // Build the text section from the functions

  Ok(CompiledProgram { text: Vec::new(), data: Vec::new() })
}

fn collect_smbols() -> Result<()> {

  Ok(())
}

