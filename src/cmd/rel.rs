use std::{
    collections::{btree_map, BTreeMap},
    fs::File,
    io::Write,
    path::PathBuf,
};

use anyhow::{bail, ensure, Context, Result};
use argh::FromArgs;

use crate::{
    analysis::{
        cfa::AnalyzerState,
        pass::{AnalysisPass, FindSaveRestSleds, FindTRKInterruptVectorTable},
        signatures::apply_signatures,
        tracker::Tracker,
    },
    array_ref_mut,
    obj::{ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSymbol, ObjSymbolKind},
    util::{
        dol::process_dol,
        elf::write_elf,
        file::{map_file, map_reader, FileIterator},
        nested::NestedMap,
        rel::process_rel,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing REL files.
#[argh(subcommand, name = "rel")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Merge(MergeArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views REL file information.
#[argh(subcommand, name = "info")]
pub struct InfoArgs {
    #[argh(positional)]
    /// REL file
    rel_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Merges a DOL + REL(s) into an ELF.
#[argh(subcommand, name = "merge")]
pub struct MergeArgs {
    #[argh(positional)]
    /// DOL file
    dol_file: PathBuf,
    #[argh(positional)]
    /// REL file(s)
    rel_files: Vec<PathBuf>,
    #[argh(option, short = 'o')]
    /// output ELF
    out_file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Merge(c_args) => merge(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let map = map_file(args.rel_file)?;
    let rel = process_rel(map_reader(&map))?;
    println!("Read REL module ID {}", rel.module_id);
    // println!("REL: {:#?}", rel);
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

fn merge(args: MergeArgs) -> Result<()> {
    log::info!("Loading {}", args.dol_file.display());
    let mut obj = process_dol(&args.dol_file)?;

    log::info!("Performing signature analysis");
    apply_signatures(&mut obj)?;
    let Some(arena_lo) = obj.arena_lo else { bail!("Failed to locate __ArenaLo in DOL") };

    let mut processed = 0;
    let mut module_map = BTreeMap::<u32, ObjInfo>::new();
    for result in FileIterator::new(&args.rel_files)? {
        let (path, entry) = result?;
        log::info!("Loading {}", path.display());
        let obj = process_rel(entry.as_reader())?;
        match module_map.entry(obj.module_id) {
            btree_map::Entry::Vacant(e) => e.insert(obj),
            btree_map::Entry::Occupied(_) => bail!("Duplicate module ID {}", obj.module_id),
        };
        processed += 1;
    }

    log::info!("Merging {} REL(s)", processed);
    let mut section_map: BTreeMap<u32, BTreeMap<u32, u32>> = BTreeMap::new();
    let mut offset = align32(arena_lo + 0x2000);
    for module in module_map.values() {
        for mod_section in &module.sections {
            let section_idx = obj.sections.len();
            ensure!(mod_section.relocations.is_empty(), "Unsupported relocations during merge");
            obj.sections.push(ObjSection {
                name: format!("{}:{}", mod_section.name, module.module_id),
                kind: mod_section.kind,
                address: offset as u64,
                size: mod_section.size,
                data: mod_section.data.clone(),
                align: mod_section.align,
                index: section_idx,
                elf_index: mod_section.elf_index,
                relocations: vec![],
                original_address: mod_section.original_address,
                file_offset: mod_section.file_offset,
                section_known: mod_section.section_known,
            });
            section_map.nested_insert(module.module_id, mod_section.elf_index as u32, offset)?;
            for (_, mod_symbol) in module.symbols.for_section(mod_section) {
                obj.symbols.add_direct(ObjSymbol {
                    name: mod_symbol.name.clone(),
                    demangled_name: mod_symbol.demangled_name.clone(),
                    address: mod_symbol.address + offset as u64,
                    section: Some(section_idx),
                    size: mod_symbol.size,
                    size_known: mod_symbol.size_known,
                    flags: mod_symbol.flags,
                    kind: mod_symbol.kind,
                    align: None,
                    data_kind: Default::default(),
                })?;
            }
            offset += align32(mod_section.size as u32);
        }
    }

    log::info!("Applying REL relocations");
    for module in module_map.values() {
        for rel_reloc in &module.unresolved_relocations {
            let source_addr = (section_map[&module.module_id][&(rel_reloc.section as u32)]
                + rel_reloc.address)
                & !3;
            let target_addr = if rel_reloc.module_id == 0 {
                rel_reloc.addend
            } else {
                let section_map = &section_map.get(&rel_reloc.module_id).with_context(|| {
                    format!("Relocation against unknown module ID {}", rel_reloc.module_id)
                })?;
                section_map[&(rel_reloc.target_section as u32)] + rel_reloc.addend
            };
            let source_section_index = obj.section_at(source_addr)?.index;
            let target_section_index = obj.section_at(target_addr)?.index;

            // Try to find a previous sized symbol that encompasses the target
            let target_symbol = {
                let mut result = None;
                for (_addr, symbol_idxs) in obj.symbols.indexes_for_range(..=target_addr).rev() {
                    let symbol_idx = if symbol_idxs.len() == 1 {
                        symbol_idxs.first().cloned().unwrap()
                    } else {
                        let mut symbol_idxs = symbol_idxs.to_vec();
                        symbol_idxs.sort_by_key(|&symbol_idx| {
                            let symbol = obj.symbols.at(symbol_idx);
                            let mut rank = match symbol.kind {
                                ObjSymbolKind::Function | ObjSymbolKind::Object => {
                                    match rel_reloc.kind {
                                        ObjRelocKind::PpcAddr16Hi
                                        | ObjRelocKind::PpcAddr16Ha
                                        | ObjRelocKind::PpcAddr16Lo => 1,
                                        ObjRelocKind::Absolute
                                        | ObjRelocKind::PpcRel24
                                        | ObjRelocKind::PpcRel14
                                        | ObjRelocKind::PpcEmbSda21 => 2,
                                    }
                                }
                                // Label
                                ObjSymbolKind::Unknown => match rel_reloc.kind {
                                    ObjRelocKind::PpcAddr16Hi
                                    | ObjRelocKind::PpcAddr16Ha
                                    | ObjRelocKind::PpcAddr16Lo
                                        if !symbol.name.starts_with("..") =>
                                    {
                                        3
                                    }
                                    _ => 1,
                                },
                                ObjSymbolKind::Section => -1,
                            };
                            if symbol.size > 0 {
                                rank += 1;
                            }
                            -rank
                        });
                        match symbol_idxs.first().cloned() {
                            Some(v) => v,
                            None => continue,
                        }
                    };
                    let symbol = obj.symbols.at(symbol_idx);
                    if symbol.address == target_addr as u64 {
                        result = Some(symbol_idx);
                        break;
                    }
                    if symbol.size > 0 {
                        if symbol.address + symbol.size > target_addr as u64 {
                            result = Some(symbol_idx);
                        }
                        break;
                    }
                }
                result
            };
            let (symbol_idx, addend) = if let Some(symbol_idx) = target_symbol {
                let symbol = obj.symbols.at(symbol_idx);
                (symbol_idx, target_addr as i64 - symbol.address as i64)
            } else {
                // Create a new label
                let symbol_idx = obj.symbols.add_direct(ObjSymbol {
                    name: String::new(),
                    demangled_name: None,
                    address: target_addr as u64,
                    section: Some(target_section_index),
                    size: 0,
                    size_known: false,
                    flags: Default::default(),
                    kind: Default::default(),
                    align: None,
                    data_kind: Default::default(),
                })?;
                (symbol_idx, 0)
            };
            obj.sections[source_section_index].relocations.push(ObjReloc {
                kind: rel_reloc.kind,
                address: source_addr as u64,
                target_symbol: symbol_idx,
                addend,
            });
        }
    }

    // Apply relocations to code/data for analyzer
    link_relocations(&mut obj)?;

    log::info!("Detecting function boundaries");
    let mut state = AnalyzerState::default();
    state.detect_functions(&obj)?;
    log::info!("Discovered {} functions", state.function_slices.len());

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    log::info!("Performing relocation analysis");
    let mut tracker = Tracker::new(&obj);
    tracker.process(&obj)?;

    log::info!("Applying relocations");
    tracker.apply(&mut obj, false)?;

    // Write ELF
    let mut file = File::create(&args.out_file)
        .with_context(|| format!("Failed to create '{}'", args.out_file.display()))?;
    log::info!("Writing {}", args.out_file.display());
    let out_object = write_elf(&obj)?;
    file.write_all(&out_object)?;
    file.flush()?;
    Ok(())
}

fn link_relocations(obj: &mut ObjInfo) -> Result<()> {
    for section in &mut obj.sections {
        for reloc in &section.relocations {
            let source_address = reloc.address /*& !3*/;
            let target_address =
                (obj.symbols.address_of(reloc.target_symbol) as i64 + reloc.addend) as u32;
            let ins_ref =
                array_ref_mut!(section.data, (source_address - section.address) as usize, 4);
            let mut ins = u32::from_be_bytes(*ins_ref);
            match reloc.kind {
                ObjRelocKind::Absolute => {
                    ins = target_address;
                }
                ObjRelocKind::PpcAddr16Hi => {
                    ins = (ins & 0xffff0000) | ((target_address >> 16) & 0xffff);
                }
                ObjRelocKind::PpcAddr16Ha => {
                    ins = (ins & 0xffff0000) | (((target_address + 0x8000) >> 16) & 0xffff);
                }
                ObjRelocKind::PpcAddr16Lo => {
                    ins = (ins & 0xffff0000) | (target_address & 0xffff);
                }
                ObjRelocKind::PpcRel24 => {
                    let diff = target_address as i32 - source_address as i32;
                    ensure!(
                        (-0x2000000..0x2000000).contains(&diff),
                        "R_PPC_REL24 relocation out of range"
                    );
                    ins = (ins & !0x3fffffc) | (diff as u32 & 0x3fffffc);
                }
                ObjRelocKind::PpcRel14 => {
                    let diff = target_address as i32 - source_address as i32;
                    ensure!(
                        (-0x2000..0x2000).contains(&diff),
                        "R_PPC_REL14 relocation out of range"
                    );
                    ins = (ins & !0xfffc) | (diff as u32 & 0xfffc);
                }
                ObjRelocKind::PpcEmbSda21 => {
                    // Unused in RELs
                }
            };
            *ins_ref = ins.to_be_bytes();
        }
    }
    Ok(())
}
