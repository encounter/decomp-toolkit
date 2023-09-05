use std::io::{Read, Seek, SeekFrom};

use anyhow::{anyhow, ensure, Result};
use byteorder::{BigEndian, ReadBytesExt};
use cwdemangle::{demangle, DemangleOptions};

use crate::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind,
    },
    util::file::{read_c_string, read_string},
};

/// For RSO references to the DOL, the sections are hardcoded.
pub const DOL_SECTION_NAMES: [Option<&str>; 14] = [
    None, // s_null
    Some(".init"),
    Some(".text"),
    Some(".ctors"),
    Some(".dtors"),
    Some(".rodata"),
    Some(".data"),
    Some(".bss"),
    Some(".sdata"),
    Some(".sdata2"),
    None, // s_zero
    Some(".sbss"),
    Some(".sbss2"),
    None, // s_zero2
];
/// ABS symbol section index.
pub const DOL_SECTION_ABS: u32 = 65521;

pub fn process_rso<R: Read + Seek>(reader: &mut R) -> Result<ObjInfo> {
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'next' to be 0");
    ensure!(reader.read_u32::<BigEndian>()? == 0, "Expected 'prev' to be 0");
    let num_sections = reader.read_u32::<BigEndian>()?;
    let section_info_offset = reader.read_u32::<BigEndian>()?;
    let name_offset = reader.read_u32::<BigEndian>()?;
    let name_size = reader.read_u32::<BigEndian>()?;
    let version = reader.read_u32::<BigEndian>()?;
    ensure!(version == 1, "Unsupported RSO version {}", version);
    let bss_size = reader.read_u32::<BigEndian>()?;
    let prolog_section = reader.read_u8()?;
    let epilog_section = reader.read_u8()?;
    let unresolved_section = reader.read_u8()?;
    ensure!(reader.read_u8()? == 0, "Expected 'bssSection' to be 0");
    let prolog_offset = reader.read_u32::<BigEndian>()?;
    let epilog_offset = reader.read_u32::<BigEndian>()?;
    let unresolved_offset = reader.read_u32::<BigEndian>()?;
    let _internal_rel_offset = reader.read_u32::<BigEndian>()?;
    let _internal_rel_size = reader.read_u32::<BigEndian>()?;
    let external_rel_offset = reader.read_u32::<BigEndian>()?;
    let external_rel_size = reader.read_u32::<BigEndian>()?;
    let export_table_offset = reader.read_u32::<BigEndian>()?;
    let export_table_size = reader.read_u32::<BigEndian>()?;
    let export_table_name_offset = reader.read_u32::<BigEndian>()?;
    let import_table_offset = reader.read_u32::<BigEndian>()?;
    let import_table_size = reader.read_u32::<BigEndian>()?;
    let import_table_name_offset = reader.read_u32::<BigEndian>()?;

    let mut sections = Vec::with_capacity(num_sections as usize);
    reader.seek(SeekFrom::Start(section_info_offset as u64))?;
    let mut total_bss_size = 0;
    for idx in 0..num_sections {
        let offset = reader.read_u32::<BigEndian>()?;
        let size = reader.read_u32::<BigEndian>()?;
        log::debug!("Section {}: offset {:#X}, size {:#X}", idx, offset, size);
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
            align: 0,
            elf_index: idx as usize,
            relocations: Default::default(),
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

    reader.seek(SeekFrom::Start(external_rel_offset as u64))?;
    while reader.stream_position()? < (external_rel_offset + external_rel_size) as u64 {
        let offset = reader.read_u32::<BigEndian>()?;
        let id_and_type = reader.read_u32::<BigEndian>()?;
        let id = (id_and_type & 0xFFFFFF00) >> 8;
        let rel_type = id_and_type & 0xFF;
        let sym_offset = reader.read_u32::<BigEndian>()?;
        log::debug!(
            "Reloc offset: {:#X}, id: {}, type: {}, sym offset: {:#X}",
            offset,
            id,
            rel_type,
            sym_offset
        );
    }

    reader.seek(SeekFrom::Start(export_table_offset as u64))?;
    while reader.stream_position()? < (export_table_offset + export_table_size) as u64 {
        let name_off = reader.read_u32::<BigEndian>()?;
        let name = read_c_string(reader, (export_table_name_offset + name_off) as u64)?;
        let sym_off = reader.read_u32::<BigEndian>()?;
        let section_idx = reader.read_u32::<BigEndian>()?;
        let hash_n = reader.read_u32::<BigEndian>()?;
        let calc = symbol_hash(&name);
        ensure!(
            hash_n == calc,
            "Mismatched calculated hash for symbol {}: {:#X} != {:#X}",
            name,
            hash_n,
            calc
        );
        let demangled_name = demangle(&name, &DemangleOptions::default());
        let section = sections
            .iter()
            .enumerate()
            .find(|&(_, section)| section.elf_index == section_idx as usize)
            .map(|(idx, _)| idx)
            // HACK: selfiles won't have any sections
            .unwrap_or(section_idx as usize);
        log::debug!(
            "Export: {}, sym off: {:#X}, section: {}, ELF hash: {:#X}",
            demangled_name.as_deref().unwrap_or(&name),
            sym_off,
            section_idx,
            hash_n
        );
        symbols.push(ObjSymbol {
            name,
            demangled_name,
            address: sym_off as u64,
            section: Some(section),
            size: 0,
            size_known: false,
            flags: Default::default(),
            kind: Default::default(),
            align: None,
            data_kind: Default::default(),
        });
    }
    reader.seek(SeekFrom::Start(import_table_offset as u64))?;
    while reader.stream_position()? < (import_table_offset + import_table_size) as u64 {
        let name_off = reader.read_u32::<BigEndian>()?;
        let name = read_c_string(reader, (import_table_name_offset + name_off) as u64)?;
        let sym_off = reader.read_u32::<BigEndian>()?;
        let section_idx = reader.read_u32::<BigEndian>()?;
        log::debug!("Import: {}, sym off: {}, section: {}", name, sym_off, section_idx);
    }

    let name = match name_offset {
        0 => String::new(),
        _ => read_string(reader, name_offset as u64, name_size as usize)?,
    };

    let obj = ObjInfo::new(ObjKind::Relocatable, ObjArchitecture::PowerPc, name, symbols, sections);
    Ok(obj)
}

fn symbol_hash(s: &str) -> u32 {
    s.bytes().fold(0u32, |hash, c| {
        let mut m = (hash << 4).wrapping_add(c as u32);
        let n = m & 0xF0000000;
        if n != 0 {
            m ^= n >> 24;
        }
        m & !n
    })
}
