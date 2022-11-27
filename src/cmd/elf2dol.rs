use std::{
    fs::File,
    io::{BufWriter, Seek, SeekFrom, Write},
};

use anyhow::{Context, Error, Result};
use argh::FromArgs;
use memmap2::MmapOptions;
use object::{Architecture, Object, ObjectKind, ObjectSection, SectionKind};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Converts an ELF file to a DOL file.
#[argh(subcommand, name = "elf2dol")]
pub struct Args {
    #[argh(positional)]
    /// path to input ELF
    elf_file: String,
    #[argh(positional)]
    /// path to output DOL
    dol_file: String,
}

#[derive(Debug, Clone, Default)]
pub struct DolSection {
    pub offset: u32,
    pub address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DolHeader {
    pub text_sections: Vec<DolSection>,
    pub data_sections: Vec<DolSection>,
    pub bss_address: u32,
    pub bss_size: u32,
    pub entry_point: u32,
}

const MAX_TEXT_SECTIONS: usize = 7;
const MAX_DATA_SECTIONS: usize = 11;
const ZERO_BUF: [u8; 32] = [0u8; 32];

pub fn run(args: Args) -> Result<()> {
    let elf_file = File::open(&args.elf_file)
        .with_context(|| format!("Failed to open ELF file '{}'", args.elf_file))?;
    let map = unsafe { MmapOptions::new().map(&elf_file) }
        .with_context(|| format!("Failed to mmap binary: '{}'", args.elf_file))?;
    let obj_file = object::read::File::parse(&*map)?;
    match obj_file.architecture() {
        Architecture::PowerPc => {}
        arch => return Err(Error::msg(format!("Unexpected architecture: {:?}", arch))),
    };
    if obj_file.is_little_endian() {
        return Err(Error::msg("Expected big endian"));
    }
    match obj_file.kind() {
        ObjectKind::Executable => {}
        kind => return Err(Error::msg(format!("Unexpected ELF type: {:?}", kind))),
    }

    let mut out = BufWriter::new(
        File::create(&args.dol_file)
            .with_context(|| format!("Failed to create DOL file '{}'", args.dol_file))?,
    );
    let mut header = DolHeader { entry_point: obj_file.entry() as u32, ..Default::default() };
    let mut offset = 0x100u32;

    // Text sections
    for section in obj_file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let address = section.address() as u32;
        let size = align32(section.size() as u32);
        header.text_sections.push(DolSection { offset, address, size });
        out.seek(SeekFrom::Start(offset as u64))?;
        write_aligned(&mut out, section.data()?)?;
        offset += size;
    }

    // Data sections
    for section in obj_file.sections() {
        if section.kind() != SectionKind::Data && section.kind() != SectionKind::ReadOnlyData {
            continue;
        }
        let address = section.address() as u32;
        let size = align32(section.size() as u32);
        header.data_sections.push(DolSection { offset, address, size });
        out.seek(SeekFrom::Start(offset as u64))?;
        write_aligned(&mut out, section.data()?)?;
        offset += size;
    }

    // BSS sections
    for section in obj_file.sections() {
        if section.kind() != SectionKind::UninitializedData {
            continue;
        }
        let address = section.address() as u32;
        let size = section.size() as u32;
        if header.bss_address == 0 {
            header.bss_address = address;
        }
        header.bss_size = (address + size) - header.bss_address;
    }

    if header.text_sections.len() > MAX_TEXT_SECTIONS {
        return Err(Error::msg(format!(
            "Too many text sections: {} / {}",
            header.text_sections.len(),
            MAX_TEXT_SECTIONS
        )));
    }
    if header.data_sections.len() > MAX_DATA_SECTIONS {
        return Err(Error::msg(format!(
            "Too many data sections: {} / {}",
            header.data_sections.len(),
            MAX_DATA_SECTIONS
        )));
    }

    // Offsets
    out.rewind()?;
    for section in &header.text_sections {
        out.write_all(&section.offset.to_be_bytes())?;
    }
    out.seek(SeekFrom::Start(0x1c))?;
    for section in &header.data_sections {
        out.write_all(&section.offset.to_be_bytes())?;
    }

    // Addresses
    out.seek(SeekFrom::Start(0x48))?;
    for section in &header.text_sections {
        out.write_all(&section.address.to_be_bytes())?;
    }
    out.seek(SeekFrom::Start(0x64))?;
    for section in &header.data_sections {
        out.write_all(&section.address.to_be_bytes())?;
    }

    // Sizes
    out.seek(SeekFrom::Start(0x90))?;
    for section in &header.text_sections {
        out.write_all(&section.size.to_be_bytes())?;
    }
    out.seek(SeekFrom::Start(0xac))?;
    for section in &header.data_sections {
        out.write_all(&section.size.to_be_bytes())?;
    }

    // BSS + entry
    out.seek(SeekFrom::Start(0xd8))?;
    out.write_all(&header.bss_address.to_be_bytes())?;
    out.write_all(&header.bss_size.to_be_bytes())?;
    out.write_all(&header.entry_point.to_be_bytes())?;

    Ok(())
}

#[inline]
fn align32(x: u32) -> u32 { (x + 31) & !31 }

#[inline]
fn write_aligned<T: Write>(out: &mut T, bytes: &[u8]) -> std::io::Result<()> {
    let len = bytes.len() as u32;
    let padding = align32(len) - len;
    out.write_all(bytes)?;
    if padding > 0 {
        out.write_all(&ZERO_BUF[0..padding as usize])?;
    }
    Ok(())
}
