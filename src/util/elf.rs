use std::{collections::BTreeMap, fs::File, path::Path};

use anyhow::{Context, Error, Result};
use cwdemangle::demangle;
use flagset::Flags;
use indexmap::IndexMap;
use memmap2::MmapOptions;
use object::{
    elf::{
        R_PPC_ADDR16_HA, R_PPC_ADDR16_HI, R_PPC_ADDR16_LO, R_PPC_ADDR32, R_PPC_EMB_SDA21,
        R_PPC_REL14, R_PPC_REL24,
    },
    write::{Mangling, SectionId, SymbolId},
    Architecture, BinaryFormat, Endianness, Object, ObjectKind, ObjectSection, ObjectSymbol,
    Relocation, RelocationEncoding, RelocationKind, RelocationTarget, SectionKind, Symbol,
    SymbolFlags, SymbolKind, SymbolScope, SymbolSection,
};

use crate::util::obj::{
    ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
    ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
};

pub fn process_elf<P: AsRef<Path>>(path: P) -> Result<ObjInfo> {
    let elf_file = File::open(&path).with_context(|| {
        format!("Failed to open ELF file '{}'", path.as_ref().to_string_lossy())
    })?;
    let map = unsafe { MmapOptions::new().map(&elf_file) }.with_context(|| {
        format!("Failed to mmap ELF file: '{}'", path.as_ref().to_string_lossy())
    })?;
    let obj_file = object::read::File::parse(&*map)?;
    let architecture = match obj_file.architecture() {
        Architecture::PowerPc => ObjArchitecture::PowerPc,
        arch => return Err(Error::msg(format!("Unexpected architecture: {arch:?}"))),
    };
    if obj_file.endianness() != Endianness::Big {
        return Err(Error::msg("Expected big endian"));
    }
    let kind = match obj_file.kind() {
        ObjectKind::Executable => ObjKind::Executable,
        ObjectKind::Relocatable => ObjKind::Relocatable,
        kind => return Err(Error::msg(format!("Unexpected ELF type: {kind:?}"))),
    };
    let mut obj_name = String::new();

    let mut stack_address: Option<u32> = None;
    let mut stack_end: Option<u32> = None;
    let mut db_stack_addr: Option<u32> = None;
    let mut arena_lo: Option<u32> = None;
    let mut arena_hi: Option<u32> = None;

    let mut sections: Vec<ObjSection> = vec![];
    let mut section_indexes: Vec<Option<usize>> = vec![];
    for section in obj_file.sections() {
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            _ => {
                section_indexes.push(None);
                continue;
            }
        };
        section_indexes.push(Some(sections.len()));
        sections.push(ObjSection {
            name: section.name()?.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section.uncompressed_data()?.to_vec(),
            align: section.align(),
            index: sections.len(),
            relocations: vec![],
            original_address: 0, // TODO load from abs symbol
            file_offset: section.file_range().map(|(v, _)| v).unwrap_or_default(),
        });
    }

    let mut symbols: Vec<ObjSymbol> = vec![];
    let mut symbol_indexes: Vec<Option<usize>> = vec![];
    let mut current_file: Option<String> = None;
    let mut section_starts = IndexMap::<String, Vec<(u64, String)>>::new();
    for symbol in obj_file.symbols() {
        // Locate linker-generated symbols
        let symbol_name = symbol.name()?;
        match symbol_name {
            "_stack_addr" => {
                stack_address = Some(symbol.address() as u32);
            }
            "_stack_end" => {
                stack_end = Some(symbol.address() as u32);
            }
            "_db_stack_addr" => {
                db_stack_addr = Some(symbol.address() as u32);
            }
            "__ArenaLo" => {
                arena_lo = Some(symbol.address() as u32);
            }
            "__ArenaHi" => {
                arena_hi = Some(symbol.address() as u32);
            }
            _ => {}
        }

        match symbol.kind() {
            // Detect file boundaries
            SymbolKind::File => {
                let file_name = symbol_name.to_string();
                if kind == ObjKind::Relocatable {
                    obj_name = file_name.clone();
                }
                match section_starts.entry(file_name.clone()) {
                    indexmap::map::Entry::Occupied(_) => {
                        return Err(Error::msg(format!("Duplicate file name: {file_name}")));
                    }
                    indexmap::map::Entry::Vacant(e) => e.insert(Default::default()),
                };
                current_file = Some(file_name);
            }
            // Detect sections within a file
            SymbolKind::Section => {
                if let Some(file_name) = &current_file {
                    let sections = section_starts
                        .get_mut(file_name)
                        .ok_or_else(|| Error::msg("Failed to create entry"))?;
                    let section_index = symbol
                        .section_index()
                        .ok_or_else(|| Error::msg("Section symbol without section"))?;
                    let section = obj_file.section_by_index(section_index)?;
                    let section_name = section.name()?.to_string();
                    sections.push((symbol.address(), section_name));
                };
            }
            // Sometimes, the section symbol address is 0,
            // so attempt to detect it from first symbol within section
            SymbolKind::Data | SymbolKind::Text => {
                if let Some(file_name) = &current_file {
                    let sections = section_starts
                        .get_mut(file_name)
                        .ok_or_else(|| Error::msg("Failed to create entry"))?;
                    let section_index = symbol.section_index().ok_or_else(|| {
                        Error::msg(format!("Section symbol without section: {symbol:?}"))
                    })?;
                    let section = obj_file.section_by_index(section_index)?;
                    let section_name = section.name()?;
                    if let Some((addr, _)) =
                        sections.iter_mut().find(|(_, name)| name == section_name)
                    {
                        if *addr == 0 {
                            *addr = symbol.address();
                        }
                    };
                };
            }
            _ => match symbol.section() {
                // Linker generated symbols indicate the end
                SymbolSection::Absolute => {
                    current_file = None;
                }
                SymbolSection::Section(_) | SymbolSection::Undefined => {}
                _ => return Err(Error::msg(format!("Unsupported symbol section type {symbol:?}"))),
            },
        }

        // Generate symbols
        if matches!(symbol.kind(), SymbolKind::Null | SymbolKind::File) {
            symbol_indexes.push(None);
            continue;
        }
        symbol_indexes.push(Some(symbols.len()));
        symbols.push(to_obj_symbol(&obj_file, &symbol, &section_indexes)?);
    }

    let mut link_order = Vec::<String>::new();
    let mut splits = BTreeMap::<u32, String>::new();
    if kind == ObjKind::Executable {
        // Link order is trivially deduced
        for file_name in section_starts.keys() {
            link_order.push(file_name.clone());
        }

        // Create a map of address -> file splits
        for (file_name, sections) in section_starts {
            for (address, _) in sections {
                splits.insert(address as u32, file_name.clone());
            }
        }

        // TODO rebuild common symbols
    }

    for (section_idx, section) in obj_file.sections().enumerate() {
        let out_section = match section_indexes[section_idx].and_then(|idx| sections.get_mut(idx)) {
            Some(s) => s,
            None => continue,
        };
        // Generate relocations
        for (address, reloc) in section.relocations() {
            out_section.relocations.push(to_obj_reloc(
                &obj_file,
                &symbol_indexes,
                &out_section.data,
                address,
                reloc,
            )?);
        }
    }

    Ok(ObjInfo {
        kind,
        architecture,
        name: obj_name,
        symbols,
        sections,
        entry: obj_file.entry() as u32,
        stack_address,
        stack_end,
        db_stack_addr,
        arena_lo,
        arena_hi,
        splits,
        link_order,
    })
}

pub fn write_elf(obj: &ObjInfo) -> Result<object::write::Object> {
    let mut out_obj =
        object::write::Object::new(BinaryFormat::Elf, Architecture::PowerPc, Endianness::Big);
    out_obj.set_mangling(Mangling::None);
    if !obj.name.is_empty() {
        out_obj.add_file_symbol(obj.name.as_bytes().to_vec());
    }

    let mut section_idxs: Vec<SectionId> = Vec::with_capacity(obj.sections.len());
    for section in &obj.sections {
        let section_id =
            out_obj.add_section(vec![], section.name.as_bytes().to_vec(), match section.kind {
                ObjSectionKind::Code => SectionKind::Text,
                ObjSectionKind::Data => SectionKind::Data,
                ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
                ObjSectionKind::Bss => SectionKind::UninitializedData,
            });
        section_idxs.push(section_id);
        let out_section = out_obj.section_mut(section_id);
        match section.kind {
            ObjSectionKind::Bss => {
                out_section.append_bss(section.size, section.align);
            }
            _ => {
                out_section.set_data(section.data.clone(), section.align);
            }
        }

        // Generate section symbol
        out_obj.section_symbol(section_id);

        // Add original addresses
        if section.original_address != 0 {
            // TODO write to metadata?
        }
        if section.file_offset != 0 {
            // TODO write to metadata?
        }
    }

    // Add symbols
    let mut symbol_idxs: Vec<SymbolId> = Vec::with_capacity(obj.symbols.len());
    for symbol in &obj.symbols {
        let symbol_id = out_obj.add_symbol(object::write::Symbol {
            name: symbol.name.as_bytes().to_vec(),
            value: symbol.address,
            size: symbol.size,
            kind: match symbol.kind {
                ObjSymbolKind::Unknown => SymbolKind::Null,
                ObjSymbolKind::Function => SymbolKind::Text,
                ObjSymbolKind::Object => SymbolKind::Data,
                ObjSymbolKind::Section => SymbolKind::Section,
            },
            scope: if symbol.flags.0.contains(ObjSymbolFlags::Hidden) {
                SymbolScope::Linkage
            } else if symbol.flags.0.contains(ObjSymbolFlags::Local) {
                SymbolScope::Compilation
            } else {
                SymbolScope::Dynamic
            },
            weak: symbol.flags.0.contains(ObjSymbolFlags::Weak),
            section: match symbol.section {
                None => object::write::SymbolSection::Undefined,
                Some(idx) => object::write::SymbolSection::Section(section_idxs[idx]),
            },
            flags: SymbolFlags::None,
        });
        symbol_idxs.push(symbol_id);
    }

    // Add relocations
    for section in &obj.sections {
        let section_id = section_idxs[section.index];
        for reloc in &section.relocations {
            let symbol_id = symbol_idxs[reloc.target_symbol];
            out_obj.add_relocation(section_id, object::write::Relocation {
                offset: reloc.address,
                size: 0,
                kind: RelocationKind::Elf(match reloc.kind {
                    ObjRelocKind::Absolute => R_PPC_ADDR32,
                    ObjRelocKind::PpcAddr16Hi => R_PPC_ADDR16_HI,
                    ObjRelocKind::PpcAddr16Ha => R_PPC_ADDR16_HA,
                    ObjRelocKind::PpcAddr16Lo => R_PPC_ADDR16_LO,
                    ObjRelocKind::PpcRel24 => R_PPC_REL24,
                    ObjRelocKind::PpcRel14 => R_PPC_REL14,
                    ObjRelocKind::PpcEmbSda21 => R_PPC_EMB_SDA21,
                }),
                encoding: RelocationEncoding::Generic,
                symbol: symbol_id,
                addend: reloc.addend,
            })?;
        }
    }

    Ok(out_obj)
}

fn to_obj_symbol(
    obj_file: &object::File<'_>,
    symbol: &Symbol<'_, '_>,
    section_indexes: &[Option<usize>],
) -> Result<ObjSymbol> {
    let section = match symbol.section_index() {
        Some(idx) => Some(obj_file.section_by_index(idx)?),
        None => None,
    };
    let name = match symbol.kind() {
        SymbolKind::Section => {
            if let Some(section) = &section {
                section.name()?
            } else {
                return Err(Error::msg("Section symbol without section"));
            }
        }
        _ => symbol.name()?,
    };
    if name.is_empty() {
        return Err(Error::msg("Empty symbol name"));
    }
    let mut flags = ObjSymbolFlagSet(ObjSymbolFlags::none());
    if symbol.is_global() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Global);
    }
    if symbol.is_local() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Local);
    }
    if symbol.is_common() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Common);
    }
    if symbol.is_weak() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Weak);
    }
    if symbol.scope() == SymbolScope::Linkage {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Hidden);
    }
    let section_idx = section.as_ref().and_then(|section| section_indexes[section.index().0]);
    Ok(ObjSymbol {
        name: name.to_string(),
        demangled_name: demangle(name, &Default::default()),
        address: symbol.address(),
        section: section_idx,
        size: symbol.size(),
        size_known: true,
        flags,
        kind: match symbol.kind() {
            SymbolKind::Text => ObjSymbolKind::Function,
            SymbolKind::Data => ObjSymbolKind::Object,
            SymbolKind::Unknown => ObjSymbolKind::Unknown,
            SymbolKind::Section => ObjSymbolKind::Section,
            _ => return Err(Error::msg(format!("Unsupported symbol kind: {:?}", symbol.kind()))),
        },
    })
}

fn to_obj_reloc(
    obj_file: &object::File<'_>,
    symbol_indexes: &[Option<usize>],
    section_data: &[u8],
    address: u64,
    reloc: Relocation,
) -> Result<ObjReloc> {
    let reloc_kind = match reloc.kind() {
        RelocationKind::Absolute => ObjRelocKind::Absolute,
        RelocationKind::Elf(kind) => match kind {
            R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
            R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
            R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
            R_PPC_REL24 => ObjRelocKind::PpcRel24,
            R_PPC_REL14 => ObjRelocKind::PpcRel14,
            R_PPC_EMB_SDA21 => ObjRelocKind::PpcEmbSda21,
            _ => return Err(Error::msg(format!("Unhandled PPC relocation type: {kind}"))),
        },
        _ => return Err(Error::msg(format!("Unhandled relocation type: {:?}", reloc.kind()))),
    };
    let symbol = match reloc.target() {
        RelocationTarget::Symbol(idx) => {
            obj_file.symbol_by_index(idx).context("Failed to locate relocation target symbol")?
        }
        _ => {
            return Err(Error::msg(format!("Unhandled relocation target: {:?}", reloc.target())));
        }
    };
    let target_symbol = symbol_indexes[symbol.index().0]
        .ok_or_else(|| Error::msg(format!("Relocation against stripped symbol: {symbol:?}")))?;
    let addend = match symbol.kind() {
        SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown => Ok(reloc.addend()),
        SymbolKind::Section => {
            let addend = if reloc.has_implicit_addend() {
                let addend = u32::from_be_bytes(
                    section_data[address as usize..address as usize + 4].try_into()?,
                ) as i64;
                match reloc_kind {
                    ObjRelocKind::Absolute => addend,
                    _ => {
                        return Err(Error::msg(format!(
                            "Unsupported implicit relocation type {reloc_kind:?}"
                        )))
                    }
                }
            } else {
                reloc.addend()
            };
            if addend < 0 {
                return Err(Error::msg(format!("Negative addend in section reloc: {addend}")));
            }
            Ok(addend)
        }
        _ => Err(Error::msg(format!("Unhandled relocation symbol type {:?}", symbol.kind()))),
    }?;
    let address = address & !3; // TODO hack: round down for instruction
    let reloc_data = ObjReloc { kind: reloc_kind, address, target_symbol, addend };
    Ok(reloc_data)
}
