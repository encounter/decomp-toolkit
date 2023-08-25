use std::{
    borrow::Cow,
    collections::{btree_map::Entry, hash_map, BTreeMap, HashMap},
    fs,
    fs::{DirBuilder, File},
    io::Write,
    mem::take,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use itertools::Itertools;
use memmap2::Mmap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span};

use crate::{
    analysis::{
        cfa::{AnalyzerState, SectionAddress},
        objects::{detect_objects, detect_strings},
        pass::{
            AnalysisPass, FindRelCtorsDtors, FindRelRodataData, FindSaveRestSleds,
            FindTRKInterruptVectorTable,
        },
        signatures::{apply_signatures, apply_signatures_post},
        tracker::Tracker,
    },
    cmd::shasum::file_sha1,
    obj::{
        best_match_for_reloc, ObjDataKind, ObjInfo, ObjReloc, ObjRelocKind, ObjSectionKind,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope, SymbolIndex,
    },
    util::{
        asm::write_asm,
        comment::MWComment,
        config::{
            apply_splits_file, apply_symbols_file, is_auto_symbol, write_splits_file,
            write_symbols_file,
        },
        dep::DepFile,
        dol::process_dol,
        elf::{process_elf, write_elf},
        file::{buf_writer, map_file, map_reader, touch, Reader},
        lcf::{asm_path_for_unit, generate_ldscript, obj_path_for_unit},
        map::apply_map_file,
        rel::process_rel,
        rso::{process_rso, DOL_SECTION_ABS, DOL_SECTION_NAMES},
        split::{is_linker_generated_object, split_obj, update_splits},
        yaz0,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DOL files.
#[argp(subcommand, name = "dol")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Split(SplitArgs),
    Diff(DiffArgs),
    Apply(ApplyArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views DOL file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// DOL file
    dol_file: PathBuf,
    #[argp(option, short = 's')]
    /// optional path to selfile.sel
    selfile: Option<PathBuf>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits a DOL into relocatable objects.
#[argp(subcommand, name = "split")]
pub struct SplitArgs {
    #[argp(positional)]
    /// input configuration file
    config: PathBuf,
    #[argp(positional)]
    /// output directory
    out_dir: PathBuf,
    #[argp(switch)]
    /// skip updating splits & symbol files (for build systems)
    no_update: bool,
    #[argp(option, short = 'j')]
    /// number of threads to use (default: number of logical CPUs)
    jobs: Option<usize>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Diffs symbols in a linked ELF.
#[argp(subcommand, name = "diff")]
pub struct DiffArgs {
    #[argp(positional)]
    /// input configuration file
    config: PathBuf,
    #[argp(positional)]
    /// linked ELF
    elf_file: PathBuf,
    #[argp(positional)]
    /// map file
    map_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Applies updated symbols from a linked ELF to the project configuration.
#[argp(subcommand, name = "apply")]
pub struct ApplyArgs {
    #[argp(positional)]
    /// input configuration file
    config: PathBuf,
    #[argp(positional)]
    /// linked ELF
    elf_file: PathBuf,
    #[argp(positional)]
    /// map file
    map_file: PathBuf,
}

#[inline]
fn bool_true() -> bool { true }

mod path_slash_serde {
    use std::path::PathBuf;

    use path_slash::PathBufExt as _;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(path: &PathBuf, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let path_str = path.to_slash().ok_or_else(|| serde::ser::Error::custom("Invalid path"))?;
        s.serialize_str(path_str.as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where D: Deserializer<'de> {
        String::deserialize(deserializer).map(PathBuf::from_slash)
    }
}

mod path_slash_serde_option {
    use std::path::PathBuf;

    use path_slash::PathBufExt as _;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(path: &Option<PathBuf>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if let Some(path) = path {
            let path_str =
                path.to_slash().ok_or_else(|| serde::ser::Error::custom("Invalid path"))?;
            s.serialize_str(path_str.as_ref())
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
    where D: Deserializer<'de> {
        Ok(Option::deserialize(deserializer)?.map(|s: String| PathBuf::from_slash(s)))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectConfig {
    #[serde(flatten)]
    pub base: ModuleConfig,
    #[serde(with = "path_slash_serde_option", default)]
    pub selfile: Option<PathBuf>,
    pub selfile_hash: Option<String>,
    /// Version of the MW `.comment` section format.
    /// If not present, no `.comment` sections will be written.
    pub mw_comment_version: Option<u8>,
    /// Disables some time-consuming analysis passes.
    /// Useful when the symbols file is already created.
    #[serde(default)]
    pub quick_analysis: bool,
    #[serde(default)]
    pub modules: Vec<ModuleConfig>,
    // Analysis options
    #[serde(default = "bool_true")]
    pub detect_objects: bool,
    #[serde(default = "bool_true")]
    pub detect_strings: bool,
    #[serde(default = "bool_true")]
    pub write_asm: bool,
    /// Adds all objects to FORCEFILES in the linker script.
    #[serde(default)]
    pub auto_force_files: bool,
    /// Specifies the start of the common BSS section.
    pub common_start: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleConfig {
    #[serde(with = "path_slash_serde")]
    pub object: PathBuf,
    pub hash: Option<String>,
    #[serde(with = "path_slash_serde_option", default)]
    pub splits: Option<PathBuf>,
    #[serde(with = "path_slash_serde_option", default)]
    pub symbols: Option<PathBuf>,
    #[serde(with = "path_slash_serde_option", default)]
    pub map: Option<PathBuf>,
}

impl ModuleConfig {
    pub fn file_name(&self) -> Cow<'_, str> {
        self.object.file_name().unwrap_or(self.object.as_os_str()).to_string_lossy()
    }

    pub fn file_prefix(&self) -> Cow<'_, str> {
        match self.file_name() {
            Cow::Borrowed(s) => {
                Cow::Borrowed(s.split_once('.').map(|(prefix, _)| prefix).unwrap_or(&s))
            }
            Cow::Owned(s) => {
                Cow::Owned(s.split_once('.').map(|(prefix, _)| prefix).unwrap_or(&s).to_string())
            }
        }
    }

    pub fn name(&self) -> Cow<'_, str> { self.file_prefix() }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputUnit {
    #[serde(with = "path_slash_serde")]
    pub object: PathBuf,
    pub name: String,
    pub autogenerated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputModule {
    pub name: String,
    pub module_id: u32,
    #[serde(with = "path_slash_serde")]
    pub ldscript: PathBuf,
    pub units: Vec<OutputUnit>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputConfig {
    #[serde(flatten)]
    pub base: OutputModule,
    pub modules: Vec<OutputModule>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Split(c_args) => split(c_args),
        SubCommand::Diff(c_args) => diff(c_args),
        SubCommand::Apply(c_args) => apply(c_args),
    }
}

fn apply_selfile(obj: &mut ObjInfo, selfile: &Path) -> Result<()> {
    log::info!("Loading {}", selfile.display());
    let rso = process_rso(selfile)?;
    for symbol in rso.symbols.iter() {
        let dol_section_index = match symbol.section {
            Some(section) => section,
            None => bail!(
                "Expected section for symbol '{}' @ {:#010X} in selfile",
                symbol.name,
                symbol.address
            ),
        };
        let (section, address, section_kind) = if dol_section_index == DOL_SECTION_ABS as usize {
            (None, symbol.address as u32, None)
        } else {
            let dol_section_name =
                DOL_SECTION_NAMES.get(dol_section_index).and_then(|&opt| opt).ok_or_else(|| {
                    anyhow!("Can't add symbol for unknown DOL section {}", dol_section_index)
                })?;
            let (dol_section_index, dol_section) = obj
                .sections
                .iter()
                .find(|&(_, section)| section.name == dol_section_name)
                .ok_or_else(|| anyhow!("Failed to locate DOL section {}", dol_section_name))?;
            (
                Some(dol_section_index),
                dol_section.address as u32 + symbol.address as u32,
                Some(dol_section.kind),
            )
        };

        let symbol_kind = match section_kind {
            Some(ObjSectionKind::Code) => ObjSymbolKind::Function,
            Some(_) => ObjSymbolKind::Object,
            None => ObjSymbolKind::Unknown,
        };
        let existing_symbols = if let Some(section_index) = section {
            obj.symbols.at_section_address(section_index, address).collect_vec()
        } else {
            // TODO hmmm
            obj.symbols.iter_abs().filter(|(_, s)| s.address == address as u64).collect_vec()
        };
        let existing_symbol = existing_symbols
            .iter()
            .find(|(_, s)| s.name == symbol.name)
            .cloned()
            .or_else(|| existing_symbols.iter().find(|(_, s)| s.kind == symbol_kind).cloned());
        if let Some((existing_symbol_idx, existing_symbol)) = existing_symbol {
            log::debug!("Mapping symbol {} to {}", symbol.name, existing_symbol.name);
            obj.symbols.replace(existing_symbol_idx, ObjSymbol {
                name: symbol.name.clone(),
                demangled_name: symbol.demangled_name.clone(),
                address: address as u64,
                section,
                size: existing_symbol.size,
                size_known: existing_symbol.size_known,
                flags: ObjSymbolFlagSet(existing_symbol.flags.0 | ObjSymbolFlags::ForceActive),
                kind: existing_symbol.kind,
                align: existing_symbol.align,
                data_kind: existing_symbol.data_kind,
            })?;
        } else {
            log::debug!("Creating symbol {} at {:#010X}", symbol.name, address);
            obj.symbols.add(
                ObjSymbol {
                    name: symbol.name.clone(),
                    demangled_name: symbol.demangled_name.clone(),
                    address: address as u64,
                    section,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global | ObjSymbolFlags::ForceActive),
                    ..*symbol
                },
                false,
            )?;
        }
    }
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let mut obj = process_dol(&args.dol_file)?;
    apply_signatures(&mut obj)?;

    let mut state = AnalyzerState::default();
    state.detect_functions(&obj)?;
    log::info!("Discovered {} functions", state.function_slices.len());

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    apply_signatures_post(&mut obj)?;

    if let Some(selfile) = &args.selfile {
        apply_selfile(&mut obj, selfile)?;
    }

    println!("{}:", obj.name);
    if let Some(entry) = obj.entry {
        println!("Entry point: {:#010X}", entry);
    }
    println!("\nSections:");
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Name", "Address", "Size", "File Off");
    for (_, section) in obj.sections.iter() {
        println!(
            "\t{: >10} | {:#010X} | {: <#10X} | {: <#10X}",
            section.name, section.address, section.size, section.file_offset
        );
    }
    println!("\nDiscovered symbols:");
    println!("\t{: >23} | {: <10} | {: <10}", "Name", "Address", "Size");
    for (_, symbol) in obj.symbols.iter_ordered().chain(obj.symbols.iter_abs()) {
        if symbol.name.starts_with('@') || is_auto_symbol(&symbol.name) {
            continue;
        }
        if symbol.size_known {
            println!("\t{: >23} | {:#010X} | {: <#10X}", symbol.name, symbol.address, symbol.size);
        } else {
            let size_str = if symbol.section.is_none() { "ABS" } else { "?" };
            println!("\t{: >23} | {:#010X} | {: <10}", symbol.name, symbol.address, size_str);
        }
    }
    println!("\n{} discovered functions from exception table", obj.known_functions.len());
    Ok(())
}

fn verify_hash<P: AsRef<Path>>(path: P, hash_str: &str) -> Result<()> {
    let mut hash_bytes = [0u8; 20];
    hex::decode_to_slice(hash_str, &mut hash_bytes)
        .with_context(|| format!("Invalid SHA-1 '{hash_str}'"))?;
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let found_hash = file_sha1(file)?;
    if found_hash.as_ref() == hash_bytes {
        Ok(())
    } else {
        Err(anyhow!(
            "Hash mismatch: expected {}, but was {}",
            hex::encode(hash_bytes),
            hex::encode(found_hash)
        ))
    }
}

type ModuleMap<'a> = BTreeMap<u32, (&'a ModuleConfig, ObjInfo)>;

fn update_symbols(obj: &mut ObjInfo, modules: &ModuleMap<'_>) -> Result<()> {
    log::debug!("Updating symbols for module {}", obj.module_id);

    // Find all references to this module from other modules
    for (source_module_id, rel_reloc) in obj
        .unresolved_relocations
        .iter()
        .map(|r| (obj.module_id, r))
        .chain(modules.iter().flat_map(|(_, (_, obj))| {
            obj.unresolved_relocations.iter().map(|r| (obj.module_id, r))
        }))
        .filter(|(_, r)| r.module_id == obj.module_id)
    {
        if source_module_id == obj.module_id {
            // Skip if already resolved
            let (_, source_section) = obj
                .sections
                .get_elf_index(rel_reloc.section as usize)
                .ok_or_else(|| anyhow!("Failed to locate REL section {}", rel_reloc.section))?;
            if source_section.relocations.contains(rel_reloc.address) {
                continue;
            }
        }

        let (target_section_index, target_section) = obj
            .sections
            .get_elf_index(rel_reloc.target_section as usize)
            .ok_or_else(|| anyhow!("Failed to locate REL section {}", rel_reloc.target_section))?;

        let target_symbols = obj
            .symbols
            .at_section_address(target_section_index, rel_reloc.addend)
            .filter(|(_, s)| s.referenced_by(rel_reloc.kind))
            .collect_vec();
        let target_symbol = best_match_for_reloc(target_symbols, rel_reloc.kind);

        if let Some((symbol_index, symbol)) = target_symbol {
            // Update symbol
            log::trace!(
                "Found symbol in section {} at {:#010X}: {}",
                rel_reloc.target_section,
                rel_reloc.addend,
                symbol.name
            );
            obj.symbols.flags(symbol_index).set_force_active(true);
        } else {
            // Add label
            log::trace!(
                "Creating label in section {} at {:#010X}",
                rel_reloc.target_section,
                rel_reloc.addend
            );
            let name = if obj.module_id == 0 {
                format!("lbl_{:08X}", rel_reloc.addend)
            } else {
                format!(
                    "lbl_{}_{}_{:X}",
                    obj.module_id,
                    target_section.name.trim_start_matches('.'),
                    rel_reloc.addend
                )
            };
            obj.symbols.add_direct(ObjSymbol {
                name,
                demangled_name: None,
                address: rel_reloc.addend as u64,
                section: Some(target_section_index),
                size: 0,
                size_known: false,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::ForceActive.into()),
                kind: Default::default(),
                align: None,
                data_kind: ObjDataKind::Unknown,
            })?;
        }
    }

    Ok(())
}

fn create_relocations(obj: &mut ObjInfo, modules: &ModuleMap<'_>, dol_obj: &ObjInfo) -> Result<()> {
    log::debug!("Creating relocations for module {}", obj.module_id);

    // Resolve all relocations in this module
    for rel_reloc in take(&mut obj.unresolved_relocations) {
        // Skip if already resolved
        let (_, source_section) = obj
            .sections
            .get_elf_index(rel_reloc.section as usize)
            .ok_or_else(|| anyhow!("Failed to locate REL section {}", rel_reloc.section))?;
        if source_section.relocations.contains(rel_reloc.address) {
            continue;
        }

        let target_obj = if rel_reloc.module_id == 0 {
            dol_obj
        } else if rel_reloc.module_id == obj.module_id {
            &*obj
        } else {
            &modules
                .get(&rel_reloc.module_id)
                .ok_or_else(|| anyhow!("Failed to locate module {}", rel_reloc.module_id))?
                .1
        };

        let (target_section_index, _target_section) = if rel_reloc.module_id == 0 {
            target_obj.sections.at_address(rel_reloc.addend)?
        } else {
            target_obj.sections.get_elf_index(rel_reloc.target_section as usize).ok_or_else(
                || {
                    anyhow!(
                        "Failed to locate module {} section {}",
                        rel_reloc.module_id,
                        rel_reloc.target_section
                    )
                },
            )?
        };

        let target_symbols = target_obj
            .symbols
            .at_section_address(target_section_index, rel_reloc.addend)
            .filter(|(_, s)| s.referenced_by(rel_reloc.kind))
            .collect_vec();
        let Some((symbol_index, symbol)) = best_match_for_reloc(target_symbols, rel_reloc.kind)
        else {
            bail!(
                "Couldn't find module {} symbol in section {} at {:#010X}",
                rel_reloc.module_id,
                rel_reloc.target_section,
                rel_reloc.addend
            );
        };

        // log::info!("Would create relocation to symbol {}", symbol.name);
        let reloc = ObjReloc {
            kind: rel_reloc.kind,
            target_symbol: symbol_index,
            addend: rel_reloc.addend as i64 - symbol.address as i64,
            module: if rel_reloc.module_id == obj.module_id {
                None
            } else {
                Some(rel_reloc.module_id)
            },
        };
        let (_, source_section) = obj
            .sections
            .get_elf_index_mut(rel_reloc.section as usize)
            .ok_or_else(|| anyhow!("Failed to locate REL section {}", rel_reloc.section))?;
        source_section.relocations.insert(rel_reloc.address, reloc)?;
    }

    Ok(())
}

fn resolve_external_relocations(
    obj: &mut ObjInfo,
    modules: &ModuleMap<'_>,
    dol_obj: Option<&ObjInfo>,
) -> Result<()> {
    log::debug!("Resolving relocations for module {}", obj.module_id);

    #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
    struct RelocRef {
        module_id: u32,
        symbol_index: SymbolIndex,
    }
    let mut reloc_to_symbol = HashMap::<RelocRef, usize>::new();

    for (_section_index, section) in obj.sections.iter_mut() {
        for (_reloc_address, reloc) in section.relocations.iter_mut() {
            if let Some(module_id) = reloc.module {
                let reloc_ref = RelocRef { module_id, symbol_index: reloc.target_symbol };
                let symbol_idx = match reloc_to_symbol.entry(reloc_ref) {
                    hash_map::Entry::Occupied(e) => *e.get(),
                    hash_map::Entry::Vacant(e) => {
                        let target_obj = if module_id == obj.module_id {
                            bail!("Relocation to self in module {}", obj.module_id)
                        } else if module_id == 0 {
                            dol_obj.unwrap()
                        } else {
                            &modules
                                .get(&module_id)
                                .ok_or_else(|| {
                                    anyhow!("Failed to locate module {}", reloc.module.unwrap())
                                })?
                                .1
                        };

                        let target_symbol = &target_obj.symbols[reloc.target_symbol];
                        let symbol_idx = obj.symbols.add_direct(ObjSymbol {
                            name: target_symbol.name.clone(),
                            demangled_name: target_symbol.demangled_name.clone(),
                            address: 0,
                            section: None,
                            size: 0,
                            size_known: false,
                            flags: Default::default(),
                            kind: Default::default(),
                            align: None,
                            data_kind: Default::default(),
                        })?;

                        e.insert(symbol_idx);
                        symbol_idx
                    }
                };

                reloc.target_symbol = symbol_idx;
                reloc.module = None;
            }
        }
    }

    Ok(())
}

fn decompress_if_needed(map: &Mmap) -> Result<Cow<[u8]>> {
    Ok(if map.len() > 4 && map[0..4] == *b"Yaz0" {
        Cow::Owned(yaz0::decompress_file(&mut map_reader(map))?)
    } else {
        Cow::Borrowed(map)
    })
}

fn load_analyze_dol(config: &ProjectConfig) -> Result<(ObjInfo, Vec<PathBuf>)> {
    // log::info!("Loading {}", config.object.display());
    if let Some(hash_str) = &config.base.hash {
        verify_hash(&config.base.object, hash_str)?;
    }
    let mut obj = process_dol(&config.base.object)?;
    let mut dep = vec![config.base.object.clone()];

    if let Some(comment_version) = config.mw_comment_version {
        obj.mw_comment = Some(MWComment::new(comment_version)?);
    }

    if let Some(map_path) = &config.base.map {
        apply_map_file(map_path, &mut obj)?;
        dep.push(map_path.clone());
    }

    if let Some(splits_path) = &config.base.splits {
        apply_splits_file(splits_path, &mut obj)?;
        dep.push(splits_path.clone());
    }

    if let Some(symbols_path) = &config.base.symbols {
        apply_symbols_file(symbols_path, &mut obj)?;
        dep.push(symbols_path.clone());
    }

    // TODO move before symbols?
    debug!("Performing signature analysis");
    apply_signatures(&mut obj)?;

    if !config.quick_analysis {
        let mut state = AnalyzerState::default();
        debug!("Detecting function boundaries");
        state.detect_functions(&obj)?;

        FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
        FindSaveRestSleds::execute(&mut state, &obj)?;
        state.apply(&mut obj)?;
    }

    apply_signatures_post(&mut obj)?;

    if let Some(selfile) = &config.selfile {
        if let Some(hash) = &config.selfile_hash {
            verify_hash(selfile, hash)?;
        }
        apply_selfile(&mut obj, selfile)?;
        dep.push(selfile.clone());
    }
    Ok((obj, dep))
}

fn split_write_obj(
    obj: &mut ObjInfo,
    config: &ProjectConfig,
    module_config: &ModuleConfig,
    out_dir: &PathBuf,
    no_update: bool,
) -> Result<OutputModule> {
    debug!("Performing relocation analysis");
    let mut tracker = Tracker::new(obj);
    tracker.process(obj)?;

    debug!("Applying relocations");
    tracker.apply(obj, false)?;

    if config.detect_objects {
        debug!("Detecting object boundaries");
        detect_objects(obj)?;
    }

    if config.detect_strings {
        debug!("Detecting strings");
        detect_strings(obj)?;
    }

    debug!("Adjusting splits");
    update_splits(obj, if obj.module_id == 0 { config.common_start } else { None })?;

    if !no_update {
        debug!("Writing configuration");
        if let Some(symbols_path) = &module_config.symbols {
            write_symbols_file(symbols_path, &obj)?;
        }
        if let Some(splits_path) = &module_config.splits {
            write_splits_file(splits_path, &obj, false)?;
        }
    }

    debug!("Splitting {} objects", obj.link_order.len());
    let split_objs = split_obj(&obj)?;

    debug!("Writing object files");
    let obj_dir = out_dir.join("obj");
    let mut out_config = OutputModule {
        name: module_config.name().to_string(),
        module_id: obj.module_id,
        ldscript: out_dir.join("ldscript.lcf"),
        units: Vec::with_capacity(split_objs.len()),
    };
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj)?;
        let out_path = obj_dir.join(obj_path_for_unit(&unit.name));
        out_config.units.push(OutputUnit {
            object: out_path.clone(),
            name: unit.name.clone(),
            autogenerated: unit.autogenerated,
        });
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        fs::write(&out_path, out_obj)
            .with_context(|| format!("Failed to write '{}'", out_path.display()))?;
    }

    // Generate ldscript.lcf
    fs::write(&out_config.ldscript, generate_ldscript(&obj, config.auto_force_files)?)?;

    debug!("Writing disassembly");
    let asm_dir = out_dir.join("asm");
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_path = asm_dir.join(asm_path_for_unit(&unit.name));

        let mut w = buf_writer(&out_path)?;
        write_asm(&mut w, split_obj)
            .with_context(|| format!("Failed to write {}", out_path.display()))?;
        w.flush()?;
    }
    Ok(out_config)
}

fn load_analyze_rel(
    config: &ProjectConfig,
    module_config: &ModuleConfig,
) -> Result<(ObjInfo, Vec<PathBuf>)> {
    debug!("Loading {}", module_config.object.display());
    if let Some(hash_str) = &module_config.hash {
        verify_hash(&module_config.object, hash_str)?;
    }
    let map = map_file(&module_config.object)?;
    let buf = decompress_if_needed(&map)?;
    let mut module_obj = process_rel(Reader::new(&buf))?;

    let mut dep = vec![module_config.object.clone()];
    if let Some(map_path) = &module_config.map {
        apply_map_file(map_path, &mut module_obj)?;
        dep.push(map_path.clone());
    }

    if let Some(splits_path) = &module_config.splits {
        apply_splits_file(splits_path, &mut module_obj)?;
        dep.push(splits_path.clone());
    }

    if let Some(symbols_path) = &module_config.symbols {
        apply_symbols_file(symbols_path, &mut module_obj)?;
        dep.push(symbols_path.clone());
    }

    debug!("Analyzing module {}", module_obj.module_id);
    if !config.quick_analysis {
        let mut state = AnalyzerState::default();
        state.detect_functions(&module_obj)?;
        FindRelCtorsDtors::execute(&mut state, &module_obj)?;
        FindRelRodataData::execute(&mut state, &module_obj)?;
        state.apply(&mut module_obj)?;
    }
    apply_signatures(&mut module_obj)?;
    apply_signatures_post(&mut module_obj)?;
    Ok((module_obj, dep))
}

fn split(args: SplitArgs) -> Result<()> {
    if let Some(jobs) = args.jobs {
        rayon::ThreadPoolBuilder::new().num_threads(jobs).build_global().unwrap();
    }

    let command_start = Instant::now();
    info!("Loading {}", args.config.display());
    let mut config_file = File::open(&args.config)
        .with_context(|| format!("Failed to open config file '{}'", args.config.display()))?;
    let config: ProjectConfig = serde_yaml::from_reader(&mut config_file)?;

    let out_config_path = args.out_dir.join("config.json");
    let mut dep = DepFile::new(out_config_path.clone());

    let module_count = config.modules.len() + 1;
    info!(
        "Loading and analyzing {} modules (using {} threads)",
        module_count,
        rayon::current_num_threads()
    );
    let mut dol_result: Option<Result<(ObjInfo, Vec<PathBuf>)>> = None;
    let mut modules_result: Option<Result<Vec<(ObjInfo, Vec<PathBuf>)>>> = None;
    let start = Instant::now();
    rayon::scope(|s| {
        // DOL
        s.spawn(|_| {
            let _span = info_span!("module", name = %config.base.name()).entered();
            dol_result =
                Some(load_analyze_dol(&config).with_context(|| {
                    format!("While loading object '{}'", config.base.file_name())
                }));
        });
        // Modules
        s.spawn(|_| {
            modules_result = Some(
                config
                    .modules
                    .par_iter()
                    .map(|module_config| {
                        let _span = info_span!("module", name = %module_config.name()).entered();
                        load_analyze_rel(&config, module_config).with_context(|| {
                            format!("While loading object '{}'", module_config.file_name())
                        })
                    })
                    .collect(),
            );
        });
    });
    let duration = start.elapsed();
    let (mut obj, dep_v) = dol_result.unwrap()?;
    let mut function_count = obj.symbols.by_kind(ObjSymbolKind::Function).count();
    dep.extend(dep_v);

    let mut modules = BTreeMap::<u32, (&ModuleConfig, ObjInfo)>::new();
    for (idx, (module_obj, dep_v)) in modules_result.unwrap()?.into_iter().enumerate() {
        function_count += module_obj.symbols.by_kind(ObjSymbolKind::Function).count();
        dep.extend(dep_v);
        match modules.entry(module_obj.module_id) {
            Entry::Vacant(e) => e.insert((&config.modules[idx], module_obj)),
            Entry::Occupied(_) => bail!("Duplicate module ID {}", obj.module_id),
        };
    }
    info!(
        "Initial analysis completed in {}.{:03}s (found {} functions)",
        duration.as_secs(),
        duration.subsec_millis(),
        function_count
    );

    if !modules.is_empty() {
        let module_ids = modules.keys().cloned().collect_vec();

        // Create any missing symbols (referenced from other modules) and set FORCEACTIVE
        update_symbols(&mut obj, &modules)?;
        for &module_id in &module_ids {
            let (module_config, mut module_obj) = modules.remove(&module_id).unwrap();
            update_symbols(&mut module_obj, &modules)?;
            modules.insert(module_id, (module_config, module_obj));
        }

        // Create relocations to symbols in other modules
        for &module_id in &module_ids {
            let (module_config, mut module_obj) = modules.remove(&module_id).unwrap();
            create_relocations(&mut module_obj, &modules, &obj)?;
            modules.insert(module_id, (module_config, module_obj));
        }

        // Replace external relocations with internal ones, creating extern symbols
        resolve_external_relocations(&mut obj, &modules, None)?;
        for &module_id in &module_ids {
            let (module_config, mut module_obj) = modules.remove(&module_id).unwrap();
            resolve_external_relocations(&mut module_obj, &modules, Some(&obj))?;
            modules.insert(module_id, (module_config, module_obj));
        }
    }

    // Create out dirs
    DirBuilder::new().recursive(true).create(&args.out_dir)?;
    touch(&args.out_dir)?;
    let include_dir = args.out_dir.join("include");
    DirBuilder::new().recursive(true).create(&include_dir)?;
    fs::write(include_dir.join("macros.inc"), include_str!("../../assets/macros.inc"))?;

    info!("Rebuilding relocations and splitting");
    let mut dol_result: Option<Result<OutputModule>> = None;
    let mut modules_result: Option<Result<Vec<OutputModule>>> = None;
    let start = Instant::now();
    rayon::scope(|s| {
        // DOL
        s.spawn(|_| {
            let _span =
                info_span!("module", name = %config.base.name(), id = obj.module_id).entered();
            dol_result = Some(
                split_write_obj(&mut obj, &config, &config.base, &args.out_dir, args.no_update)
                    .with_context(|| {
                        format!(
                            "While processing object '{}' (module ID {})",
                            config.base.file_name(),
                            obj.module_id
                        )
                    }),
            );
        });
        // Modules
        s.spawn(|_| {
            modules_result = Some(
                modules
                    .par_iter_mut()
                    .map(|(&module_id, (module_config, module_obj))| {
                        let _span =
                            info_span!("module", name = %module_config.name(), id = module_id)
                                .entered();
                        let out_dir = args.out_dir.join(module_config.name().as_ref());
                        split_write_obj(
                            module_obj,
                            &config,
                            module_config,
                            &out_dir,
                            args.no_update,
                        )
                        .with_context(|| {
                            format!(
                                "While processing object '{}' (module ID {})",
                                module_config.file_name(),
                                module_id
                            )
                        })
                    })
                    .collect(),
            );
        });
    });
    let duration = start.elapsed();
    let out_config = OutputConfig { base: dol_result.unwrap()?, modules: modules_result.unwrap()? };
    let mut object_count = out_config.base.units.len();
    for module in &out_config.modules {
        object_count += module.units.len();
    }
    info!(
        "Splitting completed in {}.{:03}s (wrote {} objects)",
        duration.as_secs(),
        duration.subsec_millis(),
        object_count
    );

    // Write output config
    {
        let mut out_file = buf_writer(&out_config_path)?;
        serde_json::to_writer_pretty(&mut out_file, &out_config)?;
        out_file.flush()?;
    }

    // Write dep file
    {
        let dep_path = args.out_dir.join("dep");
        let mut dep_file = buf_writer(dep_path)?;
        dep.write(&mut dep_file)?;
        dep_file.flush()?;
    }

    // (debugging) validate against ELF
    // if let Some(file) = &args.elf_file {
    //     validate(&obj, file, &state)?;
    // }

    let duration = command_start.elapsed();
    info!("Total duration: {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    Ok(())
}

#[allow(dead_code)]
fn validate<P: AsRef<Path>>(obj: &ObjInfo, elf_file: P, state: &AnalyzerState) -> Result<()> {
    let real_obj = process_elf(elf_file)?;
    for (section_index, real_section) in real_obj.sections.iter() {
        let obj_section = match obj.sections.get(section_index) {
            Some(v) => v,
            None => {
                log::error!("Section {} {} doesn't exist in DOL", section_index, real_section.name);
                continue;
            }
        };
        if obj_section.kind != real_section.kind || obj_section.name != real_section.name {
            log::warn!(
                "Section mismatch: {} {:?} ({}) should be {} {:?}",
                obj_section.name,
                obj_section.kind,
                section_index,
                real_section.name,
                real_section.kind
            );
        }
    }
    let mut real_functions = BTreeMap::<SectionAddress, String>::new();
    for (section_index, _section) in real_obj.sections.by_kind(ObjSectionKind::Code) {
        for (_symbol_idx, symbol) in real_obj.symbols.for_section(section_index) {
            let symbol_addr = SectionAddress::new(section_index, symbol.address as u32);
            real_functions.insert(symbol_addr, symbol.name.clone());
            match state.function_bounds.get(&symbol_addr) {
                Some(&Some(end)) => {
                    if symbol.size > 0 && end != (symbol_addr + symbol.size as u32) {
                        log::warn!(
                            "Function {:#010X} ({}) ends at {:#010X}, expected {:#010X}",
                            symbol.address,
                            symbol.name,
                            end,
                            symbol.address + symbol.size
                        );
                    }
                }
                Some(_) => {
                    log::warn!("Function {:#010X} ({}) has no end", symbol.address, symbol.name);
                }
                None => {
                    log::warn!(
                        "Function {:#010X} ({}) not discovered!",
                        symbol.address,
                        symbol.name
                    );
                }
            }
        }
    }
    for (&start, &end) in &state.function_bounds {
        let Some(end) = end else {
            continue;
        };
        if !real_functions.contains_key(&start) {
            let (real_addr, real_name) = real_functions.range(..start).next_back().unwrap();
            log::warn!(
                "Function {:#010X}..{:#010X} not real (actually a part of {} @ {:#010X})",
                start,
                end,
                real_name,
                real_addr
            );
        }
    }
    // return Ok(()); // TODO

    for (real_section_index, real_section) in real_obj.sections.iter() {
        let obj_section = match obj.sections.get(real_section_index) {
            Some(v) => v,
            None => continue,
        };
        for (real_addr, real_reloc) in real_section.relocations.iter() {
            let real_symbol = &real_obj.symbols[real_reloc.target_symbol];
            let obj_reloc = match obj_section.relocations.at(real_addr) {
                Some(v) => v,
                None => {
                    // Ignore GCC local jump branches
                    if real_symbol.kind == ObjSymbolKind::Section
                        && real_section.kind == ObjSectionKind::Code
                        && real_reloc.addend != 0
                        && matches!(
                            real_reloc.kind,
                            ObjRelocKind::PpcRel14 | ObjRelocKind::PpcRel24
                        )
                    {
                        continue;
                    }
                    log::warn!(
                        "Relocation not found @ {:#010X} {:?} to {:#010X}+{:X} ({})",
                        real_addr,
                        real_reloc.kind,
                        real_symbol.address,
                        real_reloc.addend,
                        real_symbol.demangled_name.as_ref().unwrap_or(&real_symbol.name)
                    );
                    continue;
                }
            };
            let obj_symbol = &obj.symbols[obj_reloc.target_symbol];
            if real_reloc.kind != obj_reloc.kind {
                log::warn!(
                    "Relocation type mismatch @ {:#010X}: {:?} != {:?}",
                    real_addr,
                    obj_reloc.kind,
                    real_reloc.kind
                );
                continue;
            }
            if real_symbol.address as i64 + real_reloc.addend
                != obj_symbol.address as i64 + obj_reloc.addend
            {
                log::warn!(
                    "Relocation target mismatch @ {:#010X} {:?}: {:#010X}+{:X} != {:#010X}+{:X} ({})",
                    real_addr,
                    real_reloc.kind,
                    obj_symbol.address,
                    obj_reloc.addend,
                    real_symbol.address,
                    real_reloc.addend,
                    real_symbol.demangled_name.as_ref().unwrap_or(&real_symbol.name)
                );
                continue;
            }
        }
        for (obj_addr, obj_reloc) in obj_section.relocations.iter() {
            let obj_symbol = &obj.symbols[obj_reloc.target_symbol];
            if !real_section.relocations.contains(obj_addr) {
                log::warn!(
                    "Relocation not real @ {:#010X} {:?} to {:#010X}+{:X} ({})",
                    obj_addr,
                    obj_reloc.kind,
                    obj_symbol.address,
                    obj_reloc.addend,
                    obj_symbol.demangled_name.as_ref().unwrap_or(&obj_symbol.name)
                );
                continue;
            }
        }
    }
    Ok(())
}

fn diff(args: DiffArgs) -> Result<()> {
    log::info!("Loading {}", args.config.display());
    let mut config_file = File::open(&args.config)
        .with_context(|| format!("Failed to open config file '{}'", args.config.display()))?;
    let config: ProjectConfig = serde_yaml::from_reader(&mut config_file)?;

    log::info!("Loading {}", config.base.object.display());
    let mut obj = process_dol(&config.base.object)?;

    if let Some(symbols_path) = &config.base.symbols {
        apply_symbols_file(symbols_path, &mut obj)?;
    }

    log::info!("Loading {}", args.elf_file.display());
    let mut linked_obj = process_elf(&args.elf_file)?;

    log::info!("Loading {}", args.map_file.display());
    apply_map_file(&args.map_file, &mut linked_obj)?;

    for orig_sym in obj.symbols.iter().filter(|s| s.kind != ObjSymbolKind::Section) {
        let Some(orig_section_index) = orig_sym.section else { continue };
        let orig_section = &obj.sections[orig_section_index];
        let (linked_section_index, linked_section) =
            linked_obj.sections.at_address(orig_sym.address as u32)?;

        let linked_sym = linked_obj
            .symbols
            .at_section_address(linked_section_index, orig_sym.address as u32)
            .find(|(_, sym)| sym.name == orig_sym.name)
            .or_else(|| {
                linked_obj
                    .symbols
                    .at_section_address(linked_section_index, orig_sym.address as u32)
                    .find(|(_, sym)| sym.kind == orig_sym.kind)
            });
        let mut found = false;
        if let Some((_, linked_sym)) = linked_sym {
            if linked_sym.name.starts_with(&orig_sym.name) {
                if linked_sym.size != orig_sym.size {
                    log::error!(
                        "Expected {} (type {:?}) to have size {:#X}, but found {:#X}",
                        orig_sym.name,
                        orig_sym.kind,
                        orig_sym.size,
                        linked_sym.size
                    );
                }
                found = true;
            } else if linked_sym.kind == orig_sym.kind && linked_sym.size == orig_sym.size {
                // Fuzzy match
                let orig_data = orig_section.data_range(
                    orig_sym.address as u32,
                    orig_sym.address as u32 + orig_sym.size as u32,
                )?;
                let linked_data = linked_section.data_range(
                    linked_sym.address as u32,
                    linked_sym.address as u32 + linked_sym.size as u32,
                )?;
                if orig_data == linked_data {
                    found = true;
                }
            }
        }
        if !found {
            log::error!(
                "Expected to find symbol {} (type {:?}, size {:#X}) at {:#010X}",
                orig_sym.name,
                orig_sym.kind,
                orig_sym.size,
                orig_sym.address
            );
            for (_, linked_sym) in
                linked_obj.symbols.at_section_address(linked_section_index, orig_sym.address as u32)
            {
                log::error!(
                    "At {:#010X}, found: {} (type {:?}, size {:#X})",
                    linked_sym.address,
                    linked_sym.name,
                    linked_sym.kind,
                    linked_sym.size,
                );
            }
            for (_, linked_sym) in linked_obj.symbols.for_name(&orig_sym.name) {
                log::error!(
                    "Instead, found {} (type {:?}, size {:#X}) at {:#010X}",
                    linked_sym.name,
                    linked_sym.kind,
                    linked_sym.size,
                    linked_sym.address,
                );
            }
            return Ok(());
        }
    }

    // Data diff
    for orig_sym in obj.symbols.iter().filter(|s| s.kind != ObjSymbolKind::Section) {
        let Some(orig_section_index) = orig_sym.section else { continue };
        let orig_section = &obj.sections[orig_section_index];
        let (linked_section_index, linked_section) =
            linked_obj.sections.at_address(orig_sym.address as u32)?;

        let (_, linked_sym) = linked_obj
            .symbols
            .at_section_address(linked_section_index, orig_sym.address as u32)
            .find(|(_, sym)| sym.name == orig_sym.name)
            .or_else(|| {
                linked_obj
                    .symbols
                    .at_section_address(linked_section_index, orig_sym.address as u32)
                    .find(|(_, sym)| sym.kind == orig_sym.kind)
            })
            .unwrap();

        let orig_data = orig_section
            .data_range(orig_sym.address as u32, orig_sym.address as u32 + orig_sym.size as u32)?;
        let linked_data = linked_section.data_range(
            linked_sym.address as u32,
            linked_sym.address as u32 + linked_sym.size as u32,
        )?;
        if orig_data != linked_data {
            log::error!(
                "Data mismatch for {} (type {:?}, size {:#X}) at {:#010X}",
                orig_sym.name,
                orig_sym.kind,
                orig_sym.size,
                orig_sym.address
            );
            return Ok(());
        }
    }

    log::info!("OK");
    Ok(())
}

fn apply(args: ApplyArgs) -> Result<()> {
    log::info!("Loading {}", args.config.display());
    let mut config_file = File::open(&args.config)
        .with_context(|| format!("Failed to open config file '{}'", args.config.display()))?;
    let config: ProjectConfig = serde_yaml::from_reader(&mut config_file)?;

    log::info!("Loading {}", config.base.object.display());
    let mut obj = process_dol(&config.base.object)?;

    if let Some(symbols_path) = &config.base.symbols {
        if !apply_symbols_file(symbols_path, &mut obj)? {
            bail!("Symbols file '{}' does not exist", symbols_path.display());
        }
    } else {
        bail!("No symbols file specified in config");
    }

    log::info!("Loading {}", args.elf_file.display());
    let mut linked_obj = process_elf(&args.elf_file)?;

    log::info!("Loading {}", args.map_file.display());
    apply_map_file(&args.map_file, &mut linked_obj)?;

    let mut replacements: Vec<(SymbolIndex, Option<ObjSymbol>)> = vec![];
    for (orig_idx, orig_sym) in obj.symbols.iter().enumerate() {
        // skip ABS for now
        if orig_sym.section.is_none() {
            continue;
        }
        let (linked_section_index, _linked_section) =
            linked_obj.sections.at_address(orig_sym.address as u32)?;

        let linked_sym = linked_obj
            .symbols
            .at_section_address(linked_section_index, orig_sym.address as u32)
            .find(|(_, sym)| sym.name == orig_sym.name)
            .or_else(|| {
                linked_obj
                    .symbols
                    .at_section_address(linked_section_index, orig_sym.address as u32)
                    .find(|(_, sym)| sym.kind == orig_sym.kind)
            });
        if let Some((_, linked_sym)) = linked_sym {
            let mut updated_sym = orig_sym.clone();
            let is_globalized = linked_sym.name.ends_with(&format!("_{:08X}", linked_sym.address));
            if (is_globalized && !linked_sym.name.starts_with(&orig_sym.name))
                || (!is_globalized && linked_sym.name != orig_sym.name)
            {
                log::info!(
                    "Changing name of {} (type {:?}) to {}",
                    orig_sym.name,
                    orig_sym.kind,
                    linked_sym.name
                );
                updated_sym.name = linked_sym.name.clone();
            }
            if linked_sym.size != orig_sym.size {
                log::info!(
                    "Changing size of {} (type {:?}) from {:#X} to {:#X}",
                    orig_sym.name,
                    orig_sym.kind,
                    orig_sym.size,
                    linked_sym.size
                );
                updated_sym.size = linked_sym.size;
            }
            let linked_scope = linked_sym.flags.scope();
            if linked_scope != ObjSymbolScope::Unknown
                && !is_globalized
                && linked_scope != orig_sym.flags.scope()
            {
                log::info!(
                    "Changing scope of {} (type {:?}) from {:?} to {:?}",
                    orig_sym.name,
                    orig_sym.kind,
                    orig_sym.flags.scope(),
                    linked_scope
                );
                updated_sym.flags.set_scope(linked_scope);
            }
            if updated_sym != *orig_sym {
                replacements.push((orig_idx, Some(updated_sym)));
            }
        } else {
            log::warn!(
                "Symbol not in linked ELF: {} (type {:?}, size {:#X}) at {:#010X}",
                orig_sym.name,
                orig_sym.kind,
                orig_sym.size,
                orig_sym.address
            );
            // TODO
            // replacements.push((orig_idx, None));
        }
    }

    // Add symbols from the linked object that aren't in the original
    for linked_sym in linked_obj.symbols.iter() {
        if matches!(linked_sym.kind, ObjSymbolKind::Section)
            || is_linker_generated_object(&linked_sym.name)
            // skip ABS for now
            || linked_sym.section.is_none()
        {
            continue;
        }

        let (orig_section_index, _orig_section) =
            obj.sections.at_address(linked_sym.address as u32)?;
        let orig_sym = obj
            .symbols
            .at_section_address(orig_section_index, linked_sym.address as u32)
            .find(|(_, sym)| sym.name == linked_sym.name)
            .or_else(|| {
                obj.symbols
                    .at_section_address(orig_section_index, linked_sym.address as u32)
                    .find(|(_, sym)| sym.kind == linked_sym.kind)
            });
        if orig_sym.is_none() {
            log::info!(
                "Adding symbol {} (type {:?}, size {:#X}) at {:#010X}",
                linked_sym.name,
                linked_sym.kind,
                linked_sym.size,
                linked_sym.address
            );
            obj.symbols.add_direct(ObjSymbol {
                name: linked_sym.name.clone(),
                demangled_name: linked_sym.demangled_name.clone(),
                address: linked_sym.address,
                section: Some(orig_section_index),
                size: linked_sym.size,
                size_known: linked_sym.size_known,
                flags: linked_sym.flags,
                kind: linked_sym.kind,
                align: linked_sym.align,
                data_kind: linked_sym.data_kind,
            })?;
        }
    }

    // Apply replacements
    for (idx, replacement) in replacements {
        if let Some(replacement) = replacement {
            obj.symbols.replace(idx, replacement)?;
        } else {
            // TODO
            // obj.symbols.remove(idx)?;
        }
    }

    write_symbols_file(config.base.symbols.as_ref().unwrap(), &obj)?;

    Ok(())
}
