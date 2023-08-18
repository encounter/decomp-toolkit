use std::io::Read;

use anyhow::{anyhow, bail, ensure, Result};
use byteorder::{BigEndian, ReadBytesExt};
use object::elf;

use crate::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
    util::file::Reader,
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

pub fn process_rel(mut reader: Reader) -> Result<ObjInfo> {
    let module_id = reader.read_u32::<BigEndian>()?;
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'next' to be 0");
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'prev' to be 0");
    let num_sections = reader.read_u32::<BigEndian>()?;
    let section_info_offset = reader.read_u32::<BigEndian>()?;
    let _name_offset = reader.read_u32::<BigEndian>()?;
    let _name_size = reader.read_u32::<BigEndian>()?;
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
    reader.set_position(section_info_offset as u64);
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
            let position = reader.position();
            reader.set_position(offset as u64);
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            reader.set_position(position);
            data
        };

        // println!("Section {} offset {:#X} size {:#X}", idx, offset, size);

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
            elf_index: idx as usize,
            relocations: vec![],
            original_address: 0,
            file_offset: offset as u64,
            section_known: false,
            splits: Default::default(),
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
    let mut add_symbol = |rel_section_idx: u8, offset: u32, name: &str| -> Result<()> {
        if rel_section_idx > 0 {
            let (section_index, _) = sections
                .iter()
                .enumerate()
                .find(|&(_, section)| section.elf_index == rel_section_idx as usize)
                .ok_or_else(|| anyhow!("Failed to locate {name} section {rel_section_idx}"))?;
            log::debug!("Adding {name} section {rel_section_idx} offset {offset:#X}");
            symbols.push(ObjSymbol {
                name: name.to_string(),
                demangled_name: None,
                address: offset as u64,
                section: Some(section_index),
                size: 0,
                size_known: false,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                align: None,
                data_kind: Default::default(),
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
    reader.set_position(imp_offset as u64);
    while reader.position() < imp_end {
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
                ensure!(
                    fix_size == reloc_offset,
                    "fix_size mismatch: {:#X} != {:#X}",
                    fix_size,
                    reloc_offset
                );
            }
        }

        let position = reader.position();
        reader.set_position(reloc_offset as u64);
        let mut address = 0u32;
        let mut section = u8::MAX;
        loop {
            let offset = reader.read_u16::<BigEndian>()?;
            let type_id = reader.read_u8()? as u32;
            let target_section = reader.read_u8()?;
            let addend = reader.read_u32::<BigEndian>()?;
            let kind = match type_id {
                elf::R_PPC_NONE => continue,
                elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 => ObjRelocKind::Absolute,
                // elf::R_PPC_ADDR24 => ObjRelocKind::PpcAddr24,
                // elf::R_PPC_ADDR16 => ObjRelocKind::PpcAddr16,
                elf::R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
                elf::R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
                elf::R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
                // elf::R_PPC_ADDR14 => ObjRelocKind::PpcAddr14,
                // elf::R_PPC_ADDR14_BRTAKEN => ObjRelocKind::PpcAddr14BrTaken,
                // elf::R_PPC_ADDR14_BRNTAKEN => ObjRelocKind::PpcAddr14BrnTaken,
                elf::R_PPC_REL24 => ObjRelocKind::PpcRel24,
                elf::R_PPC_REL14 => ObjRelocKind::PpcRel14,
                // elf::R_PPC_REL14_BRTAKEN => ObjRelocKind::PpcRel14BrTaken,
                // elf::R_PPC_REL14_BRNTAKEN => ObjRelocKind::PpcRel14BrnTaken,
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
        reader.set_position(position);
    }

    // let name = match name_offset {
    //     0 => String::new(),
    //     _ => read_string(&mut reader, name_offset as u64, name_size as usize).unwrap_or_default(),
    // };
    log::debug!("Read REL ID {module_id}");
    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        String::new(),
        symbols,
        sections,
    );
    obj.module_id = module_id;
    obj.unresolved_relocations = unresolved_relocations;
    Ok(obj)
}

/// REL relocation.
#[derive(Debug, Clone)]
pub struct RelReloc {
    /// Relocation kind.
    pub kind: ObjRelocKind,
    /// Source section index.
    pub section: u8,
    /// Source address.
    pub address: u32,
    /// Target module ID.
    pub module_id: u32,
    /// Target section index.
    pub target_section: u8,
    /// Target addend within section.
    /// If target module ID is 0 (DOL), this is an absolute address.
    pub addend: u32,
}
