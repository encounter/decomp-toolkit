use std::{cmp::min, collections::HashMap};

use anyhow::{Error, Result};

use crate::util::obj::{
    ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjSection, ObjSectionKind, ObjSymbol,
};

/// Split an executable object into relocatable objects.
pub fn split_obj(obj: &ObjInfo) -> Result<Vec<ObjInfo>> {
    if obj.kind != ObjKind::Executable {
        return Err(Error::msg(format!("Expected executable object, got {:?}", obj.kind)));
    }

    let mut objects: Vec<ObjInfo> = vec![];
    let mut object_symbols: Vec<Vec<Option<usize>>> = vec![];
    let mut name_to_obj: HashMap<String, usize> = HashMap::new();
    for unit in &obj.link_order {
        name_to_obj.insert(unit.clone(), objects.len());
        object_symbols.push(vec![None; obj.symbols.len()]);
        objects.push(ObjInfo {
            kind: ObjKind::Relocatable,
            architecture: ObjArchitecture::PowerPc,
            name: unit.clone(),
            symbols: vec![],
            sections: vec![],
            entry: 0,
            stack_address: None,
            stack_end: None,
            db_stack_addr: None,
            arena_lo: None,
            arena_hi: None,
            splits: Default::default(),
            link_order: vec![],
        });
    }

    for (section_idx, section) in obj.sections.iter().enumerate() {
        let mut current_address = section.address as u32;
        let mut section_end = (section.address + section.size) as u32;
        // .ctors and .dtors end with a linker-generated null pointer,
        // adjust section size appropriately
        if matches!(section.name.as_str(), ".ctors" | ".dtors")
            && section.data[section.data.len() - 4..] == [0u8; 4]
        {
            section_end -= 4;
        }
        let mut file_iter = obj.splits.range(current_address..).peekable();

        // Build address to relocation / address to symbol maps
        let relocations = section.build_relocation_map()?;
        let symbols = obj.build_symbol_map(section_idx)?;

        loop {
            if current_address >= section_end {
                break;
            }

            let (file_addr, unit) = match file_iter.next() {
                Some((&addr, unit)) => (addr, unit),
                None => return Err(Error::msg("No file found")),
            };
            if file_addr > current_address {
                return Err(Error::msg(format!(
                    "Gap in files: {} @ {:#010X}, {} @ {:#010X}",
                    section.name, section.address, unit, file_addr
                )));
            }
            let mut file_end = section_end;
            if let Some(&(&next_addr, _)) = file_iter.peek() {
                file_end = min(next_addr, section_end);
            }

            let file = name_to_obj
                .get(unit)
                .and_then(|&idx| objects.get_mut(idx))
                .ok_or_else(|| Error::msg(format!("Unit '{unit}' not in link order")))?;
            let symbol_idxs = name_to_obj
                .get(unit)
                .and_then(|&idx| object_symbols.get_mut(idx))
                .ok_or_else(|| Error::msg(format!("Unit '{unit}' not in link order")))?;
            let data = match section.kind {
                ObjSectionKind::Bss => vec![],
                _ => section.data[(current_address as u64 - section.address) as usize
                    ..(file_end as u64 - section.address) as usize]
                    .to_vec(),
            };

            // Calculate & verify section alignment
            let mut align = default_section_align(section);
            if current_address & (align as u32 - 1) != 0 {
                log::warn!(
                    "Alignment for {} {} expected {}, but starts at {:#010X}",
                    unit,
                    section.name,
                    align,
                    current_address
                );
                align = 4;
            }
            if current_address & (align as u32 - 1) != 0 {
                return Err(Error::msg(format!(
                    "Invalid alignment for split: {} {} {:#010X}",
                    unit, section.name, current_address
                )));
            }

            // Collect relocations; target_symbol will be updated later
            let out_relocations = relocations
                .range(current_address..file_end)
                .map(|(_, o)| ObjReloc {
                    kind: o.kind,
                    address: o.address - current_address as u64,
                    target_symbol: o.target_symbol,
                    addend: o.addend,
                })
                .collect();

            let out_section_idx = file.sections.len();
            file.sections.push(ObjSection {
                name: section.name.clone(),
                kind: section.kind,
                address: 0,
                size: file_end as u64 - current_address as u64,
                data,
                align,
                index: out_section_idx,
                relocations: out_relocations,
                original_address: current_address as u64,
                file_offset: section.file_offset + (current_address as u64 - section.address),
            });

            // Add section symbols
            for &symbol_idx in symbols.range(current_address..file_end).flat_map(|(_, vec)| vec) {
                if symbol_idxs[symbol_idx].is_some() {
                    continue; // should never happen?
                }
                let symbol = &obj.symbols[symbol_idx];
                symbol_idxs[symbol_idx] = Some(file.symbols.len());
                file.symbols.push(ObjSymbol {
                    name: symbol.name.clone(),
                    demangled_name: symbol.demangled_name.clone(),
                    address: symbol.address - current_address as u64,
                    section: Some(out_section_idx),
                    size: symbol.size,
                    size_known: symbol.size_known,
                    flags: symbol.flags,
                    kind: symbol.kind,
                });
            }

            current_address = file_end;
        }
    }

    // Update relocations
    for (obj_idx, out_obj) in objects.iter_mut().enumerate() {
        let symbol_idxs = &mut object_symbols[obj_idx];
        for section in &mut out_obj.sections {
            for reloc in &mut section.relocations {
                match symbol_idxs[reloc.target_symbol] {
                    Some(out_sym_idx) => {
                        reloc.target_symbol = out_sym_idx;
                    }
                    None => {
                        // Extern
                        let out_sym_idx = out_obj.symbols.len();
                        let target_sym = &obj.symbols[reloc.target_symbol];
                        symbol_idxs[reloc.target_symbol] = Some(out_sym_idx);
                        out_obj.symbols.push(ObjSymbol {
                            name: target_sym.name.clone(),
                            demangled_name: target_sym.demangled_name.clone(),
                            ..Default::default()
                        });
                        reloc.target_symbol = out_sym_idx;
                    }
                }
            }
        }
    }

    // Strip linker generated symbols
    for obj in &mut objects {
        for symbol in &mut obj.symbols {
            if is_skip_symbol(&symbol.name) {
                if symbol.section.is_some() {
                    log::debug!("Externing {:?} in {}", symbol, obj.name);
                    *symbol = ObjSymbol {
                        name: symbol.name.clone(),
                        demangled_name: symbol.demangled_name.clone(),
                        ..Default::default()
                    };
                }
            } else if is_linker_symbol(&symbol.name) {
                if let Some(section_idx) = symbol.section {
                    log::debug!("Skipping {:?} in {}", symbol, obj.name);
                    let section = &mut obj.sections[section_idx];
                    // TODO assuming end of file
                    section.size -= symbol.size;
                    section.data.truncate(section.data.len() - symbol.size as usize);
                    *symbol = ObjSymbol {
                        name: symbol.name.clone(),
                        demangled_name: symbol.demangled_name.clone(),
                        ..Default::default()
                    };
                }
            }
        }
    }

    Ok(objects)
}

/// mwld doesn't preserve the original section alignment values
fn default_section_align(section: &ObjSection) -> u64 {
    match section.kind {
        ObjSectionKind::Code => 4,
        _ => match section.name.as_str() {
            ".ctors" | ".dtors" | "extab" | "extabindex" => 4,
            _ => 8,
        },
    }
}

/// Linker-generated symbols to extern
#[inline]
fn is_skip_symbol(name: &str) -> bool { matches!(name, "_ctors" | "_dtors") }

/// Linker generated symbols to strip entirely
#[inline]
fn is_linker_symbol(name: &str) -> bool {
    matches!(name, "_eti_init_info" | "_rom_copy_info" | "_bss_init_info")
}
