use std::{path::{Path, PathBuf}, mem::size_of};

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

    /// write writes the given program as an executable elf file to disk.
    pub fn write(&mut self, program: Vec<u8>, entry_point: u64) -> Result<()> {
        // create a default header for a 64-bit x86 executable.
        let mut header = ElfHeader::default();
        header.e_entry = entry_point;

        // Build the program header table

        // Elf also can contain a section header table, but it's only needed for dynamic linking.
        // We can skip that (just don't support it)

        // Update the elf header with the program and section header information
        header.e_phoff = size_of::<ElfHeader>() as u64;
        // TODO: Set this to the size of the program header struct.
        header.e_phentsize = 16;
        header.e_phnum = 1;

        // Write the header
        
        // write the program header table

        // write the text section

        // write the data section

        Ok(())
    }
}

/// The size of the ident section at the start of the elf header.
const EI_NIDENT: usize = 16;

// These magic bytes should be at the start of the file
const MAGIC_BYTE_0: u8 = 0x7f;
const MAGIC_BYTE_1: u8 = b'E';
const MAGIC_BYTE_2: u8 = b'L';
const MAGIC_BYTE_3: u8 = b'F';

// For 32 bit applications
const _ELF_CLASS_32: u8 = 1;

// For 64 bit applications
const ELF_CLASS_64: u8 = 2;

/// Little endian with two's complement numbers
const DATA_LITTLE_ENDIAN: u8 = 1;
/// Big endian with two's complement numbers
const _DATA_BIG_ENDIAN: u8 = 1;

const VERSION_CURRENT: u8 = 1;

const LINUX_OS_ABI: u8 = 3;

/// ElfHeader is a c compatible reprensentation of an elf file's header. It should
/// be located at byte 0 in the file.
#[repr(C)]
struct ElfHeader {
    // Basic information about the elf file
    e_ident: ElfIdent,
    // Object file type
    e_type: FileType,
    // The machine architecture this elf file was made for (e.g. x86 64)
    e_machine: MachineType,
    // The version (should just be VERSION_CURRENT)
    e_version: u32,
    // The address of the entry point for executables
    e_entry: u64,
    // The program header table's offset in the file
    e_phoff: u64,
    // The section header tabke's offset in the file
    e_shoff: u64,
    // Processor specific flags. Should be 0
    e_flags: u32,
    // The size of this header in bytes
    e_ehsize: u16,
    // The size of entries in the program header table, all entries are the same size
    e_phentsize: u16,
    // The number of entries in the program header table. If this value would overflow
    // its 0xffff and the actual value is in the first program header entry's sh_info field.
    e_phnum: u16,
    // The size of entries in the section header table.
    e_shentsize: u16,
    // The number of entries in the section header table
    e_shnum: u16,
    // The index into the section table header of the entry associated with the section name
    // string table. 0 if the file has no such table.
    e_shstrndx: u16,
}

impl Default for ElfHeader {
    fn default() -> Self {
        Self {
            e_ident: ElfIdent::default(),
            e_type: FileType::Executable,
            e_machine: MachineType::X86_64,
            e_version: VERSION_CURRENT as u32,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: size_of::<Self>() as u16,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

#[repr(C)]
struct ElfIdent {
    magic_byte_0: u8,
    magic_byte_1: u8,
    magic_byte_2: u8,
    magic_byte_3: u8,
    // 32 or 64 bit
    elf_class: u8,
    // little or big endian
    data_format: u8,
    // elf version (but the linux kernel only defines a version called 'current')
    version: u8,
    // Which os to target
    target_os_abi: u8,
    // An abi version, which should always be 0 on linux (at least until now)
    abi_version: u8,
    // padding for the header to be 16 bytes long
    padding: [u8; 7],
}

impl Default for ElfIdent {
    fn default() -> Self {
        Self {
            magic_byte_0: MAGIC_BYTE_0,
            magic_byte_1: MAGIC_BYTE_1,
            magic_byte_2: MAGIC_BYTE_2,
            magic_byte_3: MAGIC_BYTE_3,
            elf_class: ELF_CLASS_64,
            data_format: DATA_LITTLE_ENDIAN,
            version: VERSION_CURRENT,
            target_os_abi: LINUX_OS_ABI,
            abi_version: 0,
            padding: [0; 7],
        }
    }
}

/// The type of the elf file
#[repr(u16)]
pub enum FileType {
    None = 0,
    Relocateable = 1,
    Executable = 2,
    Dynamic = 3,
    Core = 4,
}

/// The type of the elf file
#[repr(u16)]
pub enum MachineType {
    None = 0,
    X86_64 = 62
}

#[repr(C)]
struct ProgramHeaderTableEntry {

}

#[repr(u32)]
pub enum ProgramHeaderType {
  Null = 0,
  Load = 1,
  // There are more types defined in elf.h, but we don't need them
}
