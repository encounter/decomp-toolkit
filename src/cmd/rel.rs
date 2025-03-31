use std::{
    collections::{btree_map, BTreeMap},
    fs,
    io::{Cursor, Write},
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
use typed_path::Utf8NativePathBuf;

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
    cmd::dol::{find_object_base, ModuleConfig, ObjectBase, ProjectConfig},
    obj::{
        ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        SectionIndex as ObjSectionIndex,
    },
    util::{
        config::{is_auto_symbol, read_splits_sections, SectionDef},
        dol::process_dol,
        elf::{to_obj_reloc_kind, write_elf},
        file::{buf_writer, process_rsp, verify_hash, FileIterator},
        nested::NestedMap,
        path::native_path,
        rel::{
            print_relocations, process_rel, process_rel_header, process_rel_sections, write_rel,
            RelHeader, RelReloc, RelSectionHeader, RelWriteInfo, PERMITTED_SECTIONS,
        },
        IntoCow, ToCow,
    },
    vfs::open_file,
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
    #[argp(positional, from_str_fn(native_path))]
    /// REL file
    rel_file: Utf8NativePathBuf,
    #[argp(switch, short = 'r')]
    /// print relocations
    relocations: bool,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Merges a DOL + REL(s) into an ELF.
#[argp(subcommand, name = "merge")]
pub struct MergeArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// DOL file
    dol_file: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// REL file(s)
    rel_files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// output ELF
    out_file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates RELs from an ELF + PLF(s).
#[argp(subcommand, name = "make")]
pub struct MakeArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file(s)
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'c', from_str_fn(native_path))]
    /// (optional) project configuration file
    config: Option<Utf8NativePathBuf>,
    #[argp(option, short = 'n')]
    /// (optional) module names
    names: Vec<String>,
    #[argp(option, short = 'v')]
    /// (optional) REL version (default is 3)
    version: Option<u32>,
    #[argp(switch, short = 'w')]
    /// disable warnings
    no_warn: bool,
    #[argp(switch, short = 'q')]
    /// only print errors
    quiet: bool,
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

fn load_rel(module_config: &ModuleConfig, object_base: &ObjectBase) -> Result<RelInfo> {
    let mut file = object_base.open(&module_config.object)?;
    let data = file.map()?;
    if let Some(hash_str) = &module_config.hash {
        verify_hash(data, hash_str)?;
    }
    let mut reader = Cursor::new(data);
    let header = process_rel_header(&mut reader)?;
    let sections = process_rel_sections(&mut reader, &header)?;
    let section_defs = if let Some(splits_path) = &module_config.splits {
        read_splits_sections(&splits_path.with_encoding())?
    } else {
        None
    };
    Ok((header, sections, section_defs))
}

struct LoadedModule<'a> {
    module_id: u32,
    file: File<'a>,
    path: Utf8NativePathBuf,
}

fn resolve_relocations(
    module: &File,
    existing_headers: &BTreeMap<u32, RelInfo>,
    module_id: u32,
    symbol_map: &FxHashMap<&[u8], (u32, SymbolIndex)>,
    modules: &[LoadedModule],
    relocations: &mut Vec<RelReloc>,
) -> Result<usize> {
    let mut resolved = 0usize;
    for section in module.sections() {
        if !matches!(section.name(), Ok(name) if PERMITTED_SECTIONS.contains(&name)) {
            continue;
        }
        let section_index = if let Some((_, sections, _)) = existing_headers.get(&module_id) {
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
                        let module = modules.iter().find(|m| m.module_id == module_id).unwrap();
                        (module_id, module.file.symbol_by_index(symbol_idx).unwrap())
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
            let target_section =
                if let Some((_, sections, _)) = existing_headers.get(&target_module_id) {
                    let module = modules.iter().find(|m| m.module_id == module_id).unwrap();
                    match_section_index(&module.file, target_section_index, sections)?
                } else {
                    target_section_index.0
                } as u8;
            relocations.push(RelReloc {
                kind: to_obj_reloc_kind(reloc.flags())?,
                section: section_index,
                address: address as u32,
                module_id: target_module_id,
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

type RelInfo = (RelHeader, Vec<RelSectionHeader>, Option<Vec<SectionDef>>);

fn make(args: MakeArgs) -> Result<()> {
    let total = Instant::now();

    // Load existing REL headers (if specified)
    let mut existing_headers = BTreeMap::<u32, RelInfo>::new();
    let mut name_to_module_id = FxHashMap::<String, u32>::default();
    if let Some(config_path) = &args.config {
        let config: ProjectConfig = {
            let mut file = open_file(config_path, true)?;
            serde_yaml::from_reader(file.as_mut())?
        };
        let object_base = find_object_base(&config)?;
        for module_config in &config.modules {
            let module_name = module_config.name();
            if !args.names.is_empty() && !args.names.iter().any(|n| n == module_name) {
                continue;
            }
            let _span = info_span!("module", name = %module_name).entered();
            let info = load_rel(module_config, &object_base).with_context(|| {
                format!("While loading REL '{}'", object_base.join(&module_config.object))
            })?;
            name_to_module_id.insert(module_name.to_string(), info.0.module_id);
            match existing_headers.entry(info.0.module_id) {
                btree_map::Entry::Vacant(e) => e.insert(info),
                btree_map::Entry::Occupied(_) => {
                    bail!("Duplicate module ID {}", info.0.module_id)
                }
            };
        }
    }

    let paths = process_rsp(&args.files)?;
    if !args.quiet {
        info!("Loading {} modules", paths.len());
    }

    // Load all modules
    let mut files = paths.iter().map(|p| open_file(p, true)).collect::<Result<Vec<_>>>()?;
    let modules = files
        .par_iter_mut()
        .enumerate()
        .zip(&paths)
        .map(|((idx, file), path)| {
            // Fetch module ID by module name, if specified, to support non-sequential module IDs
            // Otherwise, use sequential module IDs starting with the DOL as 0 (default behavior)
            let module_id = args
                .names
                .get(idx)
                .and_then(|n| name_to_module_id.get(n))
                .copied()
                .unwrap_or(idx as u32);
            load_obj(file.map()?)
                .map(|o| LoadedModule { module_id, file: o, path: path.clone() })
                .with_context(|| format!("Failed to load '{}'", path))
        })
        .collect::<Result<Vec<_>>>()?;

    // Create symbol map
    let start = Instant::now();
    let mut symbol_map = FxHashMap::<&[u8], (u32, SymbolIndex)>::default();
    for module_info in modules.iter() {
        let _span = info_span!("file", path = %module_info.path).entered();
        for symbol in module_info.file.symbols() {
            if symbol.scope() == object::SymbolScope::Dynamic {
                symbol_map
                    .entry(symbol.name_bytes()?)
                    .or_insert((module_info.module_id, symbol.index()));
            }
        }
    }

    // Resolve relocations
    let mut resolved = 0usize;
    let mut relocations = Vec::<Vec<RelReloc>>::with_capacity(modules.len() - 1);
    relocations.resize_with(modules.len() - 1, Vec::new);
    for (module_info, relocations) in modules.iter().skip(1).zip(&mut relocations) {
        let _span = info_span!("file", path = %module_info.path).entered();
        resolved += resolve_relocations(
            &module_info.file,
            &existing_headers,
            module_info.module_id,
            &symbol_map,
            &modules,
            relocations,
        )
        .with_context(|| format!("While resolving relocations in '{}'", module_info.path))?;
    }

    if !args.quiet {
        let duration = start.elapsed();
        info!(
            "Symbol resolution completed in {}.{:03}s (resolved {} symbols)",
            duration.as_secs(),
            duration.subsec_millis(),
            resolved
        );
    }

    // Write RELs
    let start = Instant::now();
    for (module_info, relocations) in modules.iter().skip(1).zip(relocations) {
        let _span = info_span!("file", path = %module_info.path).entered();
        let mut info = RelWriteInfo {
            module_id: module_info.module_id,
            version: args.version.unwrap_or(3),
            name_offset: None,
            name_size: None,
            align: None,
            bss_align: None,
            section_count: None,
            quiet: args.no_warn,
            section_align: None,
            section_exec: None,
        };
        if let Some((header, section_headers, section_defs)) =
            existing_headers.get(&module_info.module_id)
        {
            info.version = header.version;
            info.name_offset = Some(header.name_offset);
            info.name_size = Some(header.name_size);
            info.align = header.align;
            info.bss_align = header.bss_align;
            info.section_count = Some(header.num_sections as usize);
            info.section_align = section_defs
                .as_ref()
                .map(|defs| defs.iter().map(|def| def.align).collect())
                .unwrap_or_default();
            info.section_exec = Some(section_headers.iter().map(|s| s.exec()).collect());
        }
        let rel_path = module_info.path.with_extension("rel");
        let mut w = buf_writer(&rel_path)?;
        write_rel(&mut w, &info, &module_info.file, relocations)
            .with_context(|| format!("Failed to write '{}'", rel_path))?;
        w.flush()?;
    }

    if !args.quiet {
        let duration = start.elapsed();
        info!("RELs written in {}.{:03}s", duration.as_secs(), duration.subsec_millis());

        let duration = total.elapsed();
        info!("Total time: {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    }
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let mut file = open_file(&args.rel_file, true)?;
    let (header, mut module_obj) = process_rel(file.as_mut(), "")?;

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

    if args.relocations {
        println!("\nRelocations:");
        println!("    [Source] section:address RelocType -> [Target] module:section:address");
        print_relocations(file.as_mut(), &header)?;
    }
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

fn merge(args: MergeArgs) -> Result<()> {
    log::info!("Loading {}", args.dol_file);
    let mut obj = {
        let mut file = open_file(&args.dol_file, true)?;
        let name = args.dol_file.file_stem().unwrap_or_default();
        process_dol(file.map()?, name)?
    };

    log::info!("Performing signature analysis");
    apply_signatures(&mut obj)?;
    let Some(arena_lo) = obj.arena_lo else { bail!("Failed to locate __ArenaLo in DOL") };

    let mut processed = 0;
    let mut module_map = BTreeMap::<u32, ObjInfo>::new();
    for result in FileIterator::new(&args.rel_files)? {
        let (path, mut entry) = result?;
        log::info!("Loading {}", path);
        let name = path.file_stem().unwrap_or_default();
        let (_, obj) = process_rel(&mut entry, name)?;
        match module_map.entry(obj.module_id) {
            btree_map::Entry::Vacant(e) => e.insert(obj),
            btree_map::Entry::Occupied(_) => bail!("Duplicate module ID {}", obj.module_id),
        };
        processed += 1;
    }

    log::info!("Merging {} REL(s)", processed);
    let mut section_map: BTreeMap<u32, BTreeMap<ObjSectionIndex, u32>> = BTreeMap::new();
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
                virtual_address: mod_section.virtual_address,
                file_offset: mod_section.file_offset,
                section_known: mod_section.section_known,
                splits: mod_section.splits.clone(),
            });
            section_map.nested_insert(module.module_id, mod_section.elf_index, offset)?;
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
                    align: mod_symbol.align,
                    data_kind: mod_symbol.data_kind,
                    name_hash: mod_symbol.name_hash,
                    demangled_name_hash: mod_symbol.demangled_name_hash,
                })?;
            }
            offset += align32(mod_section.size as u32);
        }
    }

    log::info!("Applying REL relocations");
    for module in module_map.values() {
        for rel_reloc in &module.unresolved_relocations {
            let source_addr = (section_map[&module.module_id]
                [&(rel_reloc.section as ObjSectionIndex)]
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
                    address: target_addr as u64,
                    section: Some(target_section_index),
                    ..Default::default()
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
    log::info!("Writing {}", args.out_file);
    fs::write(&args.out_file, write_elf(&obj, false)?)?;
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
