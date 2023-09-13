use std::{
    collections::{btree_map, BTreeMap},
    fs,
    io::{ Write},
    path::PathBuf,
    time::Instant,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use argp::FromArgs;
use object::{
    Architecture, Endianness, File, Object, ObjectSection, ObjectSymbol, RelocationTarget,
    SectionIndex, SymbolIndex,
};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use tracing::{info, info_span};

use crate::{
    analysis::{
        cfa::{AnalyzerState, SectionAddress},
        pass::{
            AnalysisPass, FindRelCtorsDtors, FindRelRodataData, FindSaveRestSleds,
            FindTRKInterruptVectorTable,
        },
        signatures::{apply_signatures, apply_signatures_post},
        tracker::Tracker,
    },
    array_ref_mut,
    cmd::dol::{ModuleConfig, ProjectConfig},
    obj::{ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol},
    util::{
        config::is_auto_symbol,
        dol::process_dol,
        elf::{to_obj_reloc_kind, write_elf},
        file::{buf_reader, buf_writer, map_file, process_rsp, verify_hash, FileIterator},
        nested::NestedMap,
        rel::{
            process_rel, process_rel_header, process_rel_sections, write_rel, RelHeader, RelReloc,
            RelSectionHeader, RelWriteInfo, PERMITTED_SECTIONS,
        },
        IntoCow, ToCow,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing REL files.
#[argp(subcommand, name = "rel")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Make(MakeArgs),
    Merge(MergeArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views REL file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// REL file
    rel_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Merges a DOL + REL(s) into an ELF.
#[argp(subcommand, name = "merge")]
pub struct MergeArgs {
    #[argp(positional)]
    /// DOL file
    dol_file: PathBuf,
    #[argp(positional)]
    /// REL file(s)
    rel_files: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// output ELF
    out_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates RELs from an ELF + PLF(s).
#[argp(subcommand, name = "make")]
pub struct MakeArgs {
    #[argp(positional)]
    /// input file(s)
    files: Vec<PathBuf>,
    #[argp(option, short = 'c')]
    /// (optional) project configuration file
    config: Option<PathBuf>,
    #[argp(switch, short = 'w')]
    /// disable warnings
    no_warn: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Merge(c_args) => merge(c_args),
        SubCommand::Make(c_args) => make(c_args),
    }
}

fn load_obj(buf: &[u8]) -> Result<File> {
    let obj = File::parse(buf)?;
    match obj.architecture() {
        Architecture::PowerPc => {}
        arch => bail!("Unexpected architecture: {arch:?}"),
    };
    ensure!(obj.endianness() == Endianness::Big, "Expected big endian");
    Ok(obj)
}

/// Attempt to match the section index from the ELF to the original REL.
/// Our built ELFs may be missing sections that were present in the original RELs.
fn match_section_index(
    obj: &File,
    section_index: SectionIndex,
    rel_sections: &[RelSectionHeader],
) -> Result<usize> {
    let (_, _) = (obj, rel_sections);
    Ok(section_index.0)
    // TODO
    // rel_sections
    //     .iter()
    //     .enumerate()
    //     .filter(|(_, s)| s.size() > 0)
    //     .zip(obj.sections().filter(|s| s.size() > 0))
    //     .find_map(
    //         |((rel_section_index, _), obj_section)| {
    //             if obj_section.index() == section_index {
    //                 Some(rel_section_index)
    //             } else {
    //                 None
    //             }
    //         },
    //     )
    //     .ok_or_else(|| {
    //         anyhow!(
    //             "Failed to find matching section index for {} ({}), REL section count: {}",
    //             obj.section_by_index(section_index)
    //                 .ok()
    //                 .and_then(|s| s.name().ok().map(|s| s.to_string()))
    //                 .unwrap_or("[invalid]".to_string()),
    //             section_index.0,
    //             rel_sections.len()
    //         )
    //     })
}

fn load_rel(module_config: &ModuleConfig) -> Result<(RelHeader, Vec<RelSectionHeader>)> {
    let file = map_file(&module_config.object)?;
    if let Some(hash_str) = &module_config.hash {
        verify_hash(file.as_slice(), hash_str)?;
    }
    let mut reader = file.as_reader();
    let header = process_rel_header(&mut reader)?;
    let sections = process_rel_sections(&mut reader, &header)?;
    Ok((header, sections))
}

fn resolve_relocations(
    module: &File,
    existing_headers: &BTreeMap<u32, (RelHeader, Vec<RelSectionHeader>)>,
    module_id: usize,
    symbol_map: &FxHashMap<&[u8], (usize, SymbolIndex)>,
    modules: &[(File, PathBuf)],
    relocations: &mut Vec<RelReloc>,
) -> Result<usize> {
    let mut resolved = 0usize;
    for section in module.sections() {
        if !matches!(section.name(), Ok(name) if PERMITTED_SECTIONS.contains(&name)) {
            continue;
        }
        let section_index = if let Some((_, sections)) = existing_headers.get(&(module_id as u32)) {
            match_section_index(module, section.index(), sections)?
        } else {
            section.index().0
        } as u8;
        for (address, reloc) in section.relocations() {
            let reloc_target = match reloc.target() {
                RelocationTarget::Symbol(idx) => {
                    module.symbol_by_index(idx).with_context(|| {
                        format!("Relocation against invalid symbol index {}", idx.0)
                    })?
                }
                reloc_target => bail!("Unsupported relocation target: {reloc_target:?}"),
            };
            let (target_module_id, target_symbol) = if reloc_target.is_undefined() {
                resolved += 1;
                symbol_map
                    .get(reloc_target.name_bytes()?)
                    .map(|&(module_id, symbol_idx)| {
                        (module_id, modules[module_id].0.symbol_by_index(symbol_idx).unwrap())
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "Failed to find symbol {} in any module",
                            reloc_target.name().unwrap_or("[invalid]")
                        )
                    })?
            } else {
                (module_id, reloc_target)
            };
            let target_section_index = target_symbol.section_index().unwrap();
            let target_section = if let Some((_, sections)) =
                existing_headers.get(&(target_module_id as u32))
            {
                match_section_index(&modules[target_module_id].0, target_section_index, sections)?
            } else {
                target_section_index.0
            } as u8;
            relocations.push(RelReloc {
                kind: to_obj_reloc_kind(reloc.kind())?,
                section: section_index,
                address: address as u32,
                module_id: target_module_id as u32,
                target_section,
                addend: (target_symbol.address() as i64 + reloc.addend()) as u32,
                // Extra
                original_section: section.index().0 as u8,
                original_target_section: target_section_index.0 as u8,
            });
        }
    }
    Ok(resolved)
}

fn make(args: MakeArgs) -> Result<()> {
    let total = Instant::now();

    // Load existing REL headers (if specified)
    let mut existing_headers = BTreeMap::<u32, (RelHeader, Vec<RelSectionHeader>)>::new();
    if let Some(config_path) = &args.config {
        let config: ProjectConfig = serde_yaml::from_reader(&mut buf_reader(config_path)?)?;
        for module_config in &config.modules {
            let _span = info_span!("module", name = %module_config.name()).entered();
            let (header, sections) = load_rel(module_config).with_context(|| {
                format!("While loading REL '{}'", module_config.object.display())
            })?;
            existing_headers.insert(header.module_id, (header, sections));
        }
    }

    let paths = process_rsp(&args.files)?;
    info!("Loading {} modules", paths.len());

    // Load all modules
    let files = paths.iter().map(map_file).collect::<Result<Vec<_>>>()?;
    let modules = files
        .par_iter()
        .zip(&paths)
        .map(|(file, path)| {
            load_obj(file.as_slice())
                .map(|o| (o, path.clone()))
                .with_context(|| format!("Failed to load '{}'", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    // Create symbol map
    let start = Instant::now();
    let mut symbol_map = FxHashMap::<&[u8], (usize, SymbolIndex)>::default();
    for (module_id, (module, path)) in modules.iter().enumerate() {
        let _span = info_span!("file", path = %path.display()).entered();
        for symbol in module.symbols() {
            if symbol.is_definition() && symbol.scope() == object::SymbolScope::Dynamic {
                symbol_map.entry(symbol.name_bytes()?).or_insert((module_id, symbol.index()));
            }
        }
    }

    // Resolve relocations
    let mut resolved = 0usize;
    let mut relocations = Vec::<Vec<RelReloc>>::with_capacity(modules.len() - 1);
    relocations.resize_with(modules.len() - 1, Vec::new);
    for ((module_id, (module, path)), relocations) in
        modules.iter().enumerate().skip(1).zip(&mut relocations)
    {
        let _span = info_span!("file", path = %path.display()).entered();
        resolved += resolve_relocations(
            module,
            &existing_headers,
            module_id,
            &symbol_map,
            &modules,
            relocations,
        )
        .with_context(|| format!("While resolving relocations in '{}'", path.display()))?;
    }

    let duration = start.elapsed();
    info!(
        "Symbol resolution completed in {}.{:03}s (resolved {} symbols)",
        duration.as_secs(),
        duration.subsec_millis(),
        resolved
    );

    // Write RELs
    let start = Instant::now();
    for ((module_id, (module, path)), relocations) in
        modules.iter().enumerate().skip(1).zip(relocations)
    {
        let _span = info_span!("file", path = %path.display()).entered();
        let mut info = RelWriteInfo {
            module_id: module_id as u32,
            version: 3,
            name_offset: None,
            name_size: None,
            align: None,
            bss_align: None,
            section_count: None,
            quiet: args.no_warn,
        };
        if let Some((header, _)) = existing_headers.get(&(module_id as u32)) {
            info.version = header.version;
            info.name_offset = Some(header.name_offset);
            info.name_size = Some(header.name_size);
            info.align = header.align;
            info.bss_align = header.bss_align;
            info.section_count = Some(header.num_sections as usize);
        }
        let rel_path = path.with_extension("rel");
        let mut w = buf_writer(&rel_path)?;
        write_rel(&mut w, &info, module, relocations)
            .with_context(|| format!("Failed to write '{}'", rel_path.display()))?;
        w.flush()?;
    }
    let duration = start.elapsed();
    info!("RELs written in {}.{:03}s", duration.as_secs(), duration.subsec_millis());

    let duration = total.elapsed();
    info!("Total time: {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let file = map_file(args.rel_file)?;
    let (header, mut module_obj) = process_rel(&mut file.as_reader(), "")?;

    let mut state = AnalyzerState::default();
    state.detect_functions(&module_obj)?;
    FindRelCtorsDtors::execute(&mut state, &module_obj)?;
    FindRelRodataData::execute(&mut state, &module_obj)?;
    state.apply(&mut module_obj)?;

    apply_signatures(&mut module_obj)?;
    apply_signatures_post(&mut module_obj)?;

    println!("REL module ID: {}", header.module_id);
    println!("REL version: {}", header.version);
    println!("Original section count: {}", header.num_sections);
    println!("\nSections:");
    println!(
        "{: >10} | {: <10} | {: <10} | {: <10} | {: <10}",
        "Name", "Type", "Size", "File Off", "Index"
    );
    for (_, section) in module_obj.sections.iter() {
        let kind_str = match section.kind {
            ObjSectionKind::Code => "code",
            ObjSectionKind::Data => "data",
            ObjSectionKind::ReadOnlyData => "rodata",
            ObjSectionKind::Bss => "bss",
        };
        println!(
            "{: >10} | {: <10} | {: <#10X} | {: <#10X} | {: <10}",
            section.name, kind_str, section.size, section.file_offset, section.elf_index
        );
    }
    println!("\nDiscovered symbols:");
    println!("{: >10} | {: <10} | {: <10} | {: <10}", "Section", "Address", "Size", "Name");
    for (_, symbol) in module_obj.symbols.iter_ordered() {
        if symbol.name.starts_with('@') || is_auto_symbol(symbol) {
            continue;
        }
        let section_str = if let Some(section) = symbol.section {
            module_obj.sections[section].name.as_str()
        } else {
            "ABS"
        };
        let size_str = if symbol.size_known {
            format!("{:#X}", symbol.size).into_cow()
        } else if symbol.section.is_none() {
            "ABS".to_cow()
        } else {
            "?".to_cow()
        };
        println!(
            "{: >10} | {: <#10X} | {: <10} | {: <10}",
            section_str, symbol.address, size_str, symbol.name
        );
    }
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

fn merge(args: MergeArgs) -> Result<()> {
    log::info!("Loading {}", args.dol_file.display());
    let mut obj = {
        let file = map_file(&args.dol_file)?;
        let name = args.dol_file.file_stem().map(|s| s.to_string_lossy()).unwrap_or_default();
        process_dol(file.as_slice(), name.as_ref())?
    };

    log::info!("Performing signature analysis");
    apply_signatures(&mut obj)?;
    let Some(arena_lo) = obj.arena_lo else { bail!("Failed to locate __ArenaLo in DOL") };

    let mut processed = 0;
    let mut module_map = BTreeMap::<u32, ObjInfo>::new();
    for result in FileIterator::new(&args.rel_files)? {
        let (path, entry) = result?;
        log::info!("Loading {}", path.display());
        let name = path.file_stem().map(|s| s.to_string_lossy()).unwrap_or_default();
        let (_, obj) = process_rel(&mut entry.as_reader(), name.as_ref())?;
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
        for (mod_section_index, mod_section) in module.sections.iter() {
            ensure!(mod_section.relocations.is_empty(), "Unsupported relocations during merge");
            let section_idx = obj.sections.push(ObjSection {
                name: format!("{}:{}", mod_section.name, module.module_id),
                kind: mod_section.kind,
                address: offset as u64,
                size: mod_section.size,
                data: mod_section.data.clone(),
                align: mod_section.align,
                elf_index: mod_section.elf_index,
                relocations: Default::default(),
                original_address: mod_section.original_address,
                file_offset: mod_section.file_offset,
                section_known: mod_section.section_known,
                splits: mod_section.splits.clone(),
            });
            section_map.nested_insert(module.module_id, mod_section.elf_index as u32, offset)?;
            for (_, mod_symbol) in module.symbols.for_section(mod_section_index) {
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
            let (source_section_index, _) = obj.sections.at_address(source_addr)?;
            let (target_section_index, _) = obj.sections.at_address(target_addr)?;

            let (symbol_idx, addend) = if let Some((symbol_idx, symbol)) =
                obj.symbols.for_relocation(
                    SectionAddress::new(target_section_index, target_addr),
                    rel_reloc.kind,
                )? {
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
            obj.sections[source_section_index].relocations.insert(source_addr, ObjReloc {
                kind: rel_reloc.kind,
                target_symbol: symbol_idx,
                addend,
                module: None,
            })?;
        }
    }

    // Apply relocations to code/data for analyzer
    link_relocations(&mut obj)?;

    log::info!("Detecting function boundaries");
    let mut state = AnalyzerState::default();
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.detect_functions(&obj)?;
    log::info!(
        "Discovered {} functions",
        state.functions.iter().filter(|(_, i)| i.is_function()).count()
    );

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    apply_signatures_post(&mut obj)?;

    log::info!("Performing relocation analysis");
    let mut tracker = Tracker::new(&obj);
    tracker.process(&obj)?;

    log::info!("Applying relocations");
    tracker.apply(&mut obj, false)?;

    // Write ELF
    log::info!("Writing {}", args.out_file.display());
    fs::write(&args.out_file, write_elf(&obj)?)?;
    Ok(())
}

fn link_relocations(obj: &mut ObjInfo) -> Result<()> {
    for (_, section) in obj.sections.iter_mut() {
        for (source_address, reloc) in section.relocations.iter() {
            let target_address =
                (obj.symbols[reloc.target_symbol].address as i64 + reloc.addend) as u32;
            let ins_ref =
                array_ref_mut!(section.data, (source_address as u64 - section.address) as usize, 4);
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
