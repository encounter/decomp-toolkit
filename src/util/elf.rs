use std::{collections::BTreeMap, fmt::Display, fs::File, path::Path};

use anyhow::{Context, Error, Result};
use cwdemangle::demangle;
use flagset::Flags;
use indexmap::IndexMap;
use memmap2::MmapOptions;
use object::{
    elf::{
        R_PPC_ADDR16_HA, R_PPC_ADDR16_HI, R_PPC_ADDR16_LO, R_PPC_EMB_SDA21, R_PPC_REL14,
        R_PPC_REL24,
    },
    Architecture, Object, ObjectKind, ObjectSection, ObjectSymbol, Relocation, RelocationKind,
    RelocationTarget, Section, SectionKind, Symbol, SymbolKind, SymbolSection,
};

use crate::util::obj::{
    ObjArchitecture, ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
    ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
};

pub fn process_elf<P: AsRef<Path> + Display>(path: P) -> Result<ObjInfo> {
    let elf_file =
        File::open(&path).with_context(|| format!("Failed to open ELF file '{path}'"))?;
    let map = unsafe { MmapOptions::new().map(&elf_file) }
        .with_context(|| format!("Failed to mmap ELF file: '{path}'"))?;
    let obj_file = object::read::File::parse(&*map)?;
    let architecture = match obj_file.architecture() {
        Architecture::PowerPc => ObjArchitecture::PowerPc,
        arch => return Err(Error::msg(format!("Unexpected architecture: {arch:?}"))),
    };
    if obj_file.is_little_endian() {
        return Err(Error::msg("Expected big endian"));
    }
    match obj_file.kind() {
        ObjectKind::Executable => {}
        kind => return Err(Error::msg(format!("Unexpected ELF type: {kind:?}"))),
    }

    let mut stack_address: Option<u32> = None;
    let mut stack_end: Option<u32> = None;
    let mut db_stack_addr: Option<u32> = None;
    let mut arena_lo: Option<u32> = None;
    let mut arena_hi: Option<u32> = None;

    let mut common: Vec<ObjSymbol> = vec![];
    let mut current_file: Option<String> = None;
    let mut section_starts = IndexMap::<String, Vec<(u64, String)>>::new();
    for symbol in obj_file.symbols() {
        // Locate linker-generated symbols
        let symbol_name = symbol.name()?;
        match symbol_name {
            "_stack_addr" => {
                stack_address = Some(symbol.address() as u32);
                continue;
            }
            "_stack_end" => {
                stack_end = Some(symbol.address() as u32);
                continue;
            }
            "_db_stack_addr" => {
                db_stack_addr = Some(symbol.address() as u32);
                continue;
            }
            "__ArenaLo" => {
                arena_lo = Some(symbol.address() as u32);
                continue;
            }
            "__ArenaHi" => {
                arena_hi = Some(symbol.address() as u32);
                continue;
            }
            _ => {}
        }

        match symbol.kind() {
            // Detect file boundaries
            SymbolKind::File => {
                let file_name = symbol_name.to_string();
                match section_starts.entry(file_name.clone()) {
                    indexmap::map::Entry::Occupied(_) => {
                        return Err(Error::msg(format!("Duplicate file name: {file_name}")));
                    }
                    indexmap::map::Entry::Vacant(e) => e.insert(Default::default()),
                };
                current_file = Some(file_name);
                continue;
            }
            // Detect sections within a file
            SymbolKind::Section => {
                if let Some(file_name) = &current_file {
                    let sections = match section_starts.get_mut(file_name) {
                        Some(entries) => entries,
                        None => return Err(Error::msg("Failed to create entry")),
                    };
                    let section_index = symbol
                        .section_index()
                        .ok_or_else(|| Error::msg("Section symbol without section"))?;
                    let section = obj_file.section_by_index(section_index)?;
                    let section_name = section.name()?.to_string();
                    sections.push((symbol.address(), section_name));
                };
                continue;
            }
            // Sometimes, the section symbol address is 0,
            // so attempt to detect it from first symbol within section
            SymbolKind::Data | SymbolKind::Text => {
                if let Some(file_name) = &current_file {
                    let section_map = match section_starts.get_mut(file_name) {
                        Some(entries) => entries,
                        None => return Err(Error::msg("Failed to create entry")),
                    };
                    let section_index = symbol
                        .section_index()
                        .ok_or_else(|| Error::msg("Section symbol without section"))?;
                    let section = obj_file.section_by_index(section_index)?;
                    let section_name = section.name()?;
                    if let Some((addr, _)) =
                        section_map.iter_mut().find(|(_, name)| name == section_name)
                    {
                        if *addr == 0 {
                            *addr = symbol.address();
                        }
                    };
                };
                continue;
            }
            _ => match symbol.section() {
                // Linker generated symbols indicate the end
                SymbolSection::Absolute => {
                    current_file = None;
                }
                SymbolSection::Section(_) | SymbolSection::Undefined => {}
                _ => todo!("Symbol section type {:?}", symbol),
            },
        }

        // Keep track of common symbols
        if !symbol.is_common() {
            continue;
        }
        common.push(to_obj_symbol(&obj_file, &symbol, 0)?);
    }

    // Link order is trivially deduced
    let mut link_order = Vec::<String>::new();
    for file_name in section_starts.keys() {
        link_order.push(file_name.clone());
    }

    // Create a map of address -> file splits
    let mut splits = BTreeMap::<u32, String>::new();
    for (file_name, sections) in section_starts {
        for (address, _) in sections {
            splits.insert(address as u32, file_name.clone());
        }
    }

    let mut sections: Vec<ObjSection> = vec![];
    for section in obj_file.sections() {
        let section_index = section.index();
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::Data,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            _ => continue,
        };
        let name = section.name()?;
        log::info!("Processing section {}", name);
        let data = section.uncompressed_data()?.to_vec();

        // Generate symbols
        let mut symbols: Vec<ObjSymbol> = vec![];
        for symbol in obj_file.symbols() {
            if !matches!(symbol.section_index(), Some(idx) if idx == section_index) {
                continue;
            }
            if symbol.address() == 0 || symbol.name()?.is_empty() {
                continue;
            }
            symbols.push(to_obj_symbol(&obj_file, &symbol, 0)?);
        }

        // Generate relocations
        let mut relocations: Vec<ObjReloc> = vec![];
        for (address, reloc) in section.relocations() {
            relocations.push(to_obj_reloc(&obj_file, &section, &data, address, reloc)?);
        }

        let file_offset = section.file_range().map(|(v, _)| v).unwrap_or_default();
        sections.push(ObjSection {
            name: name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data,
            index: sections.len(),
            symbols,
            relocations,
            file_offset,
        });
    }

    Ok(ObjInfo {
        architecture,
        path: path.as_ref().to_path_buf(),
        sections,
        common,
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

fn to_obj_symbol(
    obj_file: &object::File<'_>,
    symbol: &Symbol<'_, '_>,
    addend: i64,
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
    let section_address = if let Some(section) = &section {
        symbol.address() - section.address()
    } else {
        symbol.address()
    };
    Ok(ObjSymbol {
        name: name.to_string(),
        demangled_name: demangle(name, &Default::default()),
        address: symbol.address(),
        section_address,
        size: symbol.size(),
        size_known: symbol.size() != 0,
        flags,
        addend,
        kind: match symbol.kind() {
            SymbolKind::Text => ObjSymbolKind::Function,
            SymbolKind::Data => ObjSymbolKind::Object,
            _ => ObjSymbolKind::Unknown,
        },
    })
}

fn to_obj_reloc(
    obj_file: &object::File<'_>,
    _section: &Section<'_, '_>,
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
    let target_section = match symbol.section() {
        SymbolSection::Common => Some(".comm".to_string()),
        SymbolSection::Section(idx) => {
            obj_file.section_by_index(idx).and_then(|s| s.name().map(|s| s.to_string())).ok()
        }
        _ => None,
    };
    let target = match symbol.kind() {
        SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown => {
            to_obj_symbol(obj_file, &symbol, reloc.addend())
        }
        SymbolKind::Section => {
            let addend = if reloc.has_implicit_addend() {
                let addend = u32::from_be_bytes(
                    section_data[address as usize..address as usize + 4].try_into()?,
                ) as i64;
                match reloc_kind {
                    ObjRelocKind::Absolute => addend,
                    _ => todo!(),
                }
            } else {
                let addend = reloc.addend();
                if addend < 0 {
                    return Err(Error::msg(format!("Negative addend in section reloc: {addend}")));
                }
                addend
            };
            // find_section_symbol(&obj_file, &symbol, addend as u64)
            to_obj_symbol(obj_file, &symbol, addend)
        }
        _ => Err(Error::msg(format!("Unhandled relocation symbol type {:?}", symbol.kind()))),
    }?;
    let address = address & !3; // FIXME round down for instruction
    let reloc_data = ObjReloc { kind: reloc_kind, address, target, target_section };
    Ok(reloc_data)
}

// TODO needed?
#[allow(dead_code)]
fn find_section_symbol(
    obj_file: &object::File<'_>,
    target: &Symbol<'_, '_>,
    addend: u64,
) -> Result<ObjSymbol> {
    let section_index =
        target.section_index().ok_or_else(|| Error::msg("Unknown section index"))?;
    let section = obj_file.section_by_index(section_index)?;
    let target_address = target.address() + addend;

    let mut closest_symbol: Option<Symbol<'_, '_>> = None;
    for symbol in obj_file.symbols() {
        if !matches!(symbol.section_index(), Some(idx) if idx == section_index) {
            continue;
        }
        if symbol.kind() == SymbolKind::Section || symbol.address() != target_address {
            if symbol.address() < target_address
                && symbol.size() != 0
                && (closest_symbol.is_none()
                    || matches!(&closest_symbol, Some(s) if s.address() <= symbol.address()))
            {
                closest_symbol = Some(symbol);
            }
            continue;
        }
        return to_obj_symbol(obj_file, &symbol, 0);
    }

    if let Some(symbol) = closest_symbol {
        let addend = target_address - symbol.address();
        Ok(to_obj_symbol(obj_file, &symbol, addend as i64)?)
    } else {
        let addend = target_address - section.address();
        Ok(ObjSymbol {
            name: section.name()?.to_string(),
            demangled_name: None,
            address: section.address(),
            section_address: 0,
            size: section.size(),
            size_known: true,
            flags: Default::default(),
            addend: addend as i64,
            kind: ObjSymbolKind::Unknown,
        })
    }
}
