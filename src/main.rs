use std::{io::Read, path::PathBuf};

use anyhow::Result;
use pest::Parser;

pub mod parser;
pub mod elf;
pub mod compiler;


fn main() -> Result<()> {
  simple_logger::init_with_env()?;

  let mut stdin = std::io::stdin().lock();

  let mut src = String::default();
  stdin.read_to_string(&mut src)?;

  // Parse the source code
  let parsed = parser::DwarvenParser::parse(parser::Rule::program, &src)?;

  let compiled = compiler::compile(parsed)?;

  let mut path = PathBuf::new();
  path.push("out");

  let mut out = elf::ElfFile::new(&path); 
  out.write(compiled.text, compiled.data, compiled.entrypoint)?;
  
  Ok(())
}
