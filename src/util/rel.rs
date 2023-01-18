use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Result};
use byteorder::{BigEndian, ReadBytesExt};
use object::elf::{
    R_PPC_ADDR16, R_PPC_ADDR16_HA, R_PPC_ADDR16_HI, R_PPC_ADDR16_LO, R_PPC_ADDR24, R_PPC_ADDR32,
    R_PPC_NONE, R_PPC_REL14, R_PPC_REL24, R_PPC_UADDR32,
};

use crate::util::obj::{
    ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
    ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
};

/// Do not relocate anything, but accumulate the offset field for the next relocation offset calculation.
/// These types are used for referring to relocations that are more than 0xffff apart from each other.
pub const R_DOLPHIN_NOP: u32 = 201;
/// Change which section relocations are being applied to.
/// Set the offset into the section to 0.
pub const R_DOLPHIN_SECTION: u32 = 202;
/// Stop parsing the relocation list.
pub const R_DOLPHIN_END: u32 = 203;
/// Unknown.
#[allow(unused)]
pub const R_DOLPHIN_MRKREF: u32 = 204;

pub fn process_rel<P: AsRef<Path>>(path: P) -> Result<ObjInfo> {
    let mut reader = BufReader::new(File::open(&path)?);
    let module_id = reader.read_u32::<BigEndian>()?;
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'next' to be 0");
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'prev' to be 0");
    let num_sections = reader.read_u32::<BigEndian>()?;
    let section_info_offset = reader.read_u32::<BigEndian>()?;
    let name_offset = reader.read_u32::<BigEndian>()?;
    let name_size = reader.read_u32::<BigEndian>()?;
    let version = reader.read_u32::<BigEndian>()?;
    ensure!(matches!(version, 1..=3), "Unsupported REL version {}", version);
    let bss_size = reader.read_u32::<BigEndian>()?;
    let rel_offset = reader.read_u32::<BigEndian>()?;
    let imp_offset = reader.read_u32::<BigEndian>()?;
    let imp_size = reader.read_u32::<BigEndian>()?;
    let prolog_section = reader.read_u8()?;
    let epilog_section = reader.read_u8()?;
    let unresolved_section = reader.read_u8()?;
    ensure!(reader.read_u8()? == 0, "Expected 'bssSection' to be 0");
    let prolog_offset = reader.read_u32::<BigEndian>()?;
    let epilog_offset = reader.read_u32::<BigEndian>()?;
    let unresolved_offset = reader.read_u32::<BigEndian>()?;
    let (align, bss_align) = if version >= 2 {
        let align = reader.read_u32::<BigEndian>()?;
        let bss_align = reader.read_u32::<BigEndian>()?;
        (Some(align), Some(bss_align))
    } else {
        (None, None)
    };
    let fix_size = if version >= 3 { Some(reader.read_u32::<BigEndian>()?) } else { None };

    let mut sections = Vec::with_capacity(num_sections as usize);
    reader.seek(SeekFrom::Start(section_info_offset as u64))?;
    let mut total_bss_size = 0;
    for idx in 0..num_sections {
        let offset = reader.read_u32::<BigEndian>()?;
        let size = reader.read_u32::<BigEndian>()?;
        if size == 0 {
            continue;
        }
        let exec = (offset & 1) == 1;
        let offset = offset & !3;

        let data = if offset == 0 {
            vec![]
        } else {
            let position = reader.stream_position()?;
            reader.seek(SeekFrom::Start(offset as u64))?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            reader.seek(SeekFrom::Start(position))?;
            data
        };

        // println!("Section {} offset {:#X} size {:#X}", idx, offset, size);

        let index = sections.len();
        sections.push(ObjSection {
            name: format!(".section{}", idx),
            kind: if offset == 0 {
                ObjSectionKind::Bss
            } else if exec {
                ObjSectionKind::Code
            } else {
                ObjSectionKind::Data
            },
            address: 0,
            size: size as u64,
            data,
            align: match offset {
                0 => bss_align,
                _ => align,
            }
            .unwrap_or_default() as u64,
            index,
            elf_index: idx as usize,
            relocations: vec![],
            original_address: 0,
            file_offset: offset as u64,
            section_known: false,
        });
        if offset == 0 {
            total_bss_size += size;
        }
    }
    ensure!(
        total_bss_size == bss_size,
        "Mismatched BSS size: {:#X} != {:#X}",
        total_bss_size,
        bss_size
    );

    let mut symbols = Vec::new();
    let mut add_symbol = |section_idx: u8, offset: u32, name: &str| -> Result<()> {
        if section_idx > 0 {
            let section = sections
                .iter()
                .find(|section| section.elf_index == section_idx as usize)
                .ok_or_else(|| anyhow!("Failed to locate {name} section {section_idx}"))?;
            log::info!("Adding {name} section {section_idx} offset {offset:#X}");
            symbols.push(ObjSymbol {
                name: name.to_string(),
                demangled_name: None,
                address: offset as u64,
                section: Some(section.index),
                size: 0,
                size_known: false,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
            });
        }
        Ok(())
    };
    add_symbol(prolog_section, prolog_offset, "_prolog")?;
    add_symbol(epilog_section, epilog_offset, "_epilog")?;
    add_symbol(unresolved_section, unresolved_offset, "_unresolved")?;

    let mut unresolved_relocations = Vec::new();
    let mut imp_idx = 0;
    let imp_end = (imp_offset + imp_size) as u64;
    reader.seek(SeekFrom::Start(imp_offset as u64))?;
    while reader.stream_position()? < imp_end {
        let reloc_module_id = reader.read_u32::<BigEndian>()?;
        let reloc_offset = reader.read_u32::<BigEndian>()?;

        if imp_idx == 0 {
            ensure!(
                reloc_offset == rel_offset,
                "imp index 0 offset mismatch: {:#X} != {:#X}",
                reloc_offset,
                rel_offset
            );
        }
        imp_idx += 1;

        if reloc_module_id == module_id {
            if let Some(fix_size) = fix_size {
                ensure!(fix_size == reloc_offset, "fix_size mismatch: {:#X} != {:#X}", fix_size, reloc_offset);
            }
        }

        let position = reader.stream_position()?;
        reader.seek(SeekFrom::Start(reloc_offset as u64))?;
        let mut address = 0u32;
        let mut section = u8::MAX;
        loop {
            let offset = reader.read_u16::<BigEndian>()?;
            let type_id = reader.read_u8()? as u32;
            let target_section = reader.read_u8()?;
            let addend = reader.read_u32::<BigEndian>()?;
            let kind = match type_id {
                R_PPC_NONE => continue,
                R_PPC_ADDR32 | R_PPC_UADDR32 => ObjRelocKind::Absolute,
                // R_PPC_ADDR24 => ObjRelocKind::PpcAddr24,
                // R_PPC_ADDR16 => ObjRelocKind::PpcAddr16,
                R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
                R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
                R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
                // R_PPC_ADDR14 => ObjRelocKind::PpcAddr14,
                // R_PPC_ADDR14_BRTAKEN => ObjRelocKind::PpcAddr14BrTaken,
                // R_PPC_ADDR14_BRNTAKEN => ObjRelocKind::PpcAddr14BrnTaken,
                R_PPC_REL24 => ObjRelocKind::PpcRel24,
                R_PPC_REL14 => ObjRelocKind::PpcRel14,
                // R_PPC_REL14_BRTAKEN => ObjRelocKind::PpcRel14BrTaken,
                // R_PPC_REL14_BRNTAKEN => ObjRelocKind::PpcRel14BrnTaken,
                R_DOLPHIN_NOP => {
                    address += offset as u32;
                    continue;
                }
                R_DOLPHIN_SECTION => {
                    address = 0;
                    section = target_section;
                    continue;
                }
                R_DOLPHIN_END => break,
                // R_DOLPHIN_MRKREF => ?
                reloc_type => bail!("Unhandled REL relocation type {reloc_type}"),
            };
            address += offset as u32;
            unresolved_relocations.push(RelReloc {
                kind,
                section,
                address,
                module_id: reloc_module_id,
                target_section,
                addend,
            });
        }
        reader.seek(SeekFrom::Start(position))?;
    }

    Ok(ObjInfo {
        module_id,
        kind: ObjKind::Relocatable,
        architecture: ObjArchitecture::PowerPc,
        name: "".to_string(),
        symbols,
        sections,
        entry: 0,
        sda2_base: None,
        sda_base: None,
        stack_address: None,
        stack_end: None,
        db_stack_addr: None,
        arena_lo: None,
        arena_hi: None,
        splits: Default::default(),
        link_order: vec![],
        known_functions: Default::default(),
        unresolved_relocations,
    })
}

#[derive(Debug, Clone)]
pub struct RelReloc {
    pub kind: ObjRelocKind,
    pub section: u8,
    pub address: u32,
    pub module_id: u32,
    pub target_section: u8,
    pub addend: u32,
}
