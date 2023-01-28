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
        tracker::Tracker,
    },
    cmd::dol::apply_signatures,
    obj::{ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolKind},
    util::{
        dol::process_dol,
        elf::write_elf,
        nested::{NestedMap, NestedVec},
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
    let rel = process_rel(&args.rel_file)?;
    println!("Read REL module ID {}", rel.module_id);
    // println!("REL: {:#?}", rel);
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

fn merge(args: MergeArgs) -> Result<()> {
    let mut module_map = BTreeMap::<u32, ObjInfo>::new();
    log::info!("Loading {}", args.dol_file.display());
    let mut obj = process_dol(&args.dol_file)?;
    apply_signatures(&mut obj)?;

    for path in &args.rel_files {
        log::info!("Loading {}", path.display());
        let obj = process_rel(path)?;
        match module_map.entry(obj.module_id) {
            btree_map::Entry::Vacant(e) => e.insert(obj),
            btree_map::Entry::Occupied(_) => bail!("Duplicate module ID {}", obj.module_id),
        };
    }
    let mut section_map: BTreeMap<u32, BTreeMap<u32, u32>> = BTreeMap::new();
    let mut offset = align32(obj.arena_lo.unwrap() + 0x2000);
    for (_, module) in &module_map {
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
            let symbols = module.symbols_for_section(mod_section.index);
            for (_, mod_symbol) in symbols {
                obj.symbols.push(ObjSymbol {
                    name: mod_symbol.name.clone(),
                    demangled_name: mod_symbol.demangled_name.clone(),
                    address: mod_symbol.address + offset as u64,
                    section: Some(section_idx),
                    size: mod_symbol.size,
                    size_known: mod_symbol.size_known,
                    flags: mod_symbol.flags,
                    kind: mod_symbol.kind,
                });
            }
            offset += align32(mod_section.size as u32);
        }
    }

    let mut symbol_maps = Vec::new();
    for section in &obj.sections {
        symbol_maps.push(obj.build_symbol_map(section.index)?);
    }

    // Apply relocations
    for (_, module) in &module_map {
        for rel_reloc in &module.unresolved_relocations {
            let source_addr =
                section_map[&module.module_id][&(rel_reloc.section as u32)] + rel_reloc.address;
            let target_addr = if rel_reloc.module_id == 0 {
                rel_reloc.addend
            } else {
                let base = section_map[&rel_reloc.module_id][&(rel_reloc.target_section as u32)];
                let addend = rel_reloc.addend;
                base + addend
            };
            let source_section = obj.section_at(source_addr)?;
            let target_section = obj.section_at(target_addr)?;
            let target_section_index = target_section.index;

            // Try to find a previous sized symbol that encompasses the target
            let sym_map = &mut symbol_maps[target_section_index];
            let target_symbol = {
                let mut result = None;
                for (_addr, symbol_idxs) in sym_map.range(..=target_addr).rev() {
                    let symbol_idx = if symbol_idxs.len() == 1 {
                        symbol_idxs.first().cloned().unwrap()
                    } else {
                        let mut symbol_idxs = symbol_idxs.clone();
                        symbol_idxs.sort_by_key(|&symbol_idx| {
                            let symbol = &obj.symbols[symbol_idx];
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
                    let symbol = &obj.symbols[symbol_idx];
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
                let symbol = &obj.symbols[symbol_idx];
                (symbol_idx, target_addr as i64 - symbol.address as i64)
            } else {
                // Create a new label
                let symbol_idx = obj.symbols.len();
                obj.symbols.push(ObjSymbol {
                    name: String::new(),
                    demangled_name: None,
                    address: target_addr as u64,
                    section: Some(target_section_index),
                    size: 0,
                    size_known: false,
                    flags: Default::default(),
                    kind: Default::default(),
                });
                sym_map.nested_push(target_addr, symbol_idx);
                (symbol_idx, 0)
            };
            obj.sections[target_section_index].relocations.push(ObjReloc {
                kind: rel_reloc.kind,
                address: source_addr as u64,
                target_symbol: symbol_idx,
                addend,
            });
        }
    }

    // Apply known functions from extab
    let mut state = AnalyzerState::default();
    for (&addr, &size) in &obj.known_functions {
        state.function_entries.insert(addr);
        state.function_bounds.insert(addr, addr + size);
    }
    for symbol in &obj.symbols {
        if symbol.kind != ObjSymbolKind::Function {
            continue;
        }
        state.function_entries.insert(symbol.address as u32);
        if !symbol.size_known {
            continue;
        }
        state.function_bounds.insert(symbol.address as u32, (symbol.address + symbol.size) as u32);
    }
    // Also check the start of each code section
    for section in &obj.sections {
        if section.kind == ObjSectionKind::Code {
            state.function_entries.insert(section.address as u32);
        }
    }

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
    let out_object = write_elf(&obj)?;
    file.write_all(&out_object)?;
    file.flush()?;
    Ok(())
}
