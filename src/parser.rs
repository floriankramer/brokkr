use anyhow::Result;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "dwarven.pest"]
pub struct DwarvenParser;

pub fn verify(src: String) -> Result<()> {
  DwarvenParser::parse(Rule::program, &src)?;

  Ok(())
}
