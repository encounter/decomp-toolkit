use std::{
    fs::File,
    io::{BufWriter, Seek, SeekFrom, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use argh::FromArgs;
use object::{Architecture, Endianness, Object, ObjectKind, ObjectSection, SectionKind};

use crate::util::file::map_file;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Converts an ELF file to a DOL file.
#[argh(subcommand, name = "elf2dol")]
pub struct Args {
    #[argh(positional)]
    /// path to input ELF
    elf_file: PathBuf,
    #[argh(positional)]
    /// path to output DOL
    dol_file: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct DolSection {
    pub offset: u32,
    pub address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DolHeader {
    pub text_section_count: usize,
    pub data_section_count: usize,
    pub text_sections: [DolSection; MAX_TEXT_SECTIONS],
    pub data_sections: [DolSection; MAX_DATA_SECTIONS],
    pub bss_address: u32,
    pub bss_size: u32,
    pub entry_point: u32,
}

const MAX_TEXT_SECTIONS: usize = 7;
const MAX_DATA_SECTIONS: usize = 11;

pub fn run(args: Args) -> Result<()> {
    let map = map_file(&args.elf_file)?;
    let obj_file = object::read::File::parse(&*map)?;
    match obj_file.architecture() {
        Architecture::PowerPc => {}
        arch => bail!("Unexpected architecture: {arch:?}"),
    };
    ensure!(obj_file.endianness() == Endianness::Big, "Expected big endian");
    match obj_file.kind() {
        ObjectKind::Executable => {}
        kind => bail!("Unexpected ELF type: {kind:?}"),
    }

    let mut header = DolHeader { entry_point: obj_file.entry() as u32, ..Default::default() };
    let mut offset = 0x100u32;
    let mut out = BufWriter::new(
        File::create(&args.dol_file)
            .with_context(|| format!("Failed to create DOL file '{}'", args.dol_file.display()))?,
    );
    out.seek(SeekFrom::Start(offset as u64))?;

    // Text sections
    for section in
        obj_file.sections().filter(|s| section_kind(s) == SectionKind::Text && is_alloc(s.flags()))
    {
        log::debug!("Processing text section '{}'", section.name().unwrap_or("[error]"));
        let address = section.address() as u32;
        let size = align32(section.size() as u32);
        *header.text_sections.get_mut(header.text_section_count).ok_or_else(|| {
            anyhow!(
                "Too many text sections (while processing '{}')",
                section.name().unwrap_or("[error]")
            )
        })? = DolSection { offset, address, size };
        header.text_section_count += 1;
        write_aligned(&mut out, section.data()?, size)?;
        offset += size;
    }

    // Data sections
    for section in
        obj_file.sections().filter(|s| section_kind(s) == SectionKind::Data && is_alloc(s.flags()))
    {
        log::debug!("Processing data section '{}'", section.name().unwrap_or("[error]"));
        let address = section.address() as u32;
        let size = align32(section.size() as u32);
        *header.data_sections.get_mut(header.data_section_count).ok_or_else(|| {
            anyhow!(
                "Too many data sections (while processing '{}')",
                section.name().unwrap_or("[error]")
            )
        })? = DolSection { offset, address, size };
        header.data_section_count += 1;
        write_aligned(&mut out, section.data()?, size)?;
        offset += size;
    }

    // BSS sections
    for section in obj_file
        .sections()
        .filter(|s| section_kind(s) == SectionKind::UninitializedData && is_alloc(s.flags()))
    {
        let address = section.address() as u32;
        let size = section.size() as u32;
        if header.bss_address == 0 {
            header.bss_address = address;
        }
        header.bss_size = (address + size) - header.bss_address;
    }

    // Offsets
    out.rewind()?;
    for section in &header.text_sections {
        out.write_all(&section.offset.to_be_bytes())?;
    }
    for section in &header.data_sections {
        out.write_all(&section.offset.to_be_bytes())?;
    }

    // Addresses
    for section in &header.text_sections {
        out.write_all(&section.address.to_be_bytes())?;
    }
    for section in &header.data_sections {
        out.write_all(&section.address.to_be_bytes())?;
    }

    // Sizes
    for section in &header.text_sections {
        out.write_all(&section.size.to_be_bytes())?;
    }
    for section in &header.data_sections {
        out.write_all(&section.size.to_be_bytes())?;
    }

    // BSS + entry
    out.write_all(&header.bss_address.to_be_bytes())?;
    out.write_all(&header.bss_size.to_be_bytes())?;
    out.write_all(&header.entry_point.to_be_bytes())?;

    // Done!
    out.flush()?;
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

const ZERO_BUF: [u8; 32] = [0u8; 32];

#[inline]
fn write_aligned<T: Write>(out: &mut T, bytes: &[u8], aligned_size: u32) -> std::io::Result<()> {
    out.write_all(bytes)?;
    let padding = aligned_size - bytes.len() as u32;
    if padding > 0 {
        out.write_all(&ZERO_BUF[0..padding as usize])?;
    }
    Ok(())
}

// Some ELF files don't have the proper section kind set (for small data sections in particular)
// so we map the section name to the expected section kind when possible.
#[inline]
fn section_kind(section: &object::Section) -> SectionKind {
    section
        .name()
        .ok()
        .and_then(|name| match name {
            ".init" | ".text" | ".vmtext" | ".dbgtext" => Some(SectionKind::Text),
            ".ctors" | ".dtors" | ".data" | ".rodata" | ".sdata" | ".sdata2" | "extab"
            | "extabindex" => Some(SectionKind::Data),
            ".bss" | ".sbss" | ".sbss2" => Some(SectionKind::UninitializedData),
            _ => None,
        })
        .unwrap_or_else(|| match section.kind() {
            SectionKind::ReadOnlyData => SectionKind::Data,
            kind => kind,
        })
}

#[inline]
fn is_alloc(flags: object::SectionFlags) -> bool {
    matches!(flags, object::SectionFlags::Elf { sh_flags } if sh_flags & object::elf::SHF_ALLOC as u64 != 0)
}
