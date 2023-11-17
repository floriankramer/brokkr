use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "dwarven.pest"]
pub struct DwarvenParser;
