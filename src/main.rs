use std::io::Read;

use anyhow::Result;

pub mod parser;
pub mod elf;


fn main() -> Result<()> {
  let mut stdin = std::io::stdin().lock();

  let mut src = String::default();
  stdin.read_to_string(&mut src)?;

  // Parse the source code
  parser::verify(src)?;

  // Collect global symbol information (functions and values)

  // Build the data section from globals

  // Build the text section from the functions
  
  Ok(())
}
