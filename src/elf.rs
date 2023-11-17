use std::path::{Path, PathBuf};

use anyhow::Result;

pub struct ElfFile {
    path: PathBuf,
}

impl ElfFile {
    pub fn new(path: &Path) -> ElfFile {
        ElfFile {
            path: path.to_owned(),
        }
    }

    pub fn write(text_section: Vec<u8>, data_section: Vec<u8>) -> Result<()> {
        Ok(())
    }
}
