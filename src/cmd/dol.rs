use std::{
    borrow::Cow,
    cmp::min,
    collections::{btree_map::Entry, hash_map, BTreeMap, HashMap},
    ffi::OsStr,
    fs,
    fs::DirBuilder,
    io::{Cursor, Write},
    mem::take,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use cwdemangle::demangle;
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    analysis::{
        cfa::{AnalyzerState, SectionAddress},
        objects::{detect_objects, detect_strings},
        pass::{
            AnalysisPass, FindRelCtorsDtors, FindRelRodataData, FindSaveRestSleds,
            FindTRKInterruptVectorTable,
        },
        signatures::{apply_signatures, apply_signatures_post, update_ctors_dtors},
        tracker::Tracker,
    },
    cmd::shasum::file_sha1_string,
    obj::{
        best_match_for_reloc, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope, SymbolIndex,
    },
    util::{
        asm::write_asm,
        bin2c::bin2c,
        comment::MWComment,
        config::{
            apply_splits_file, apply_symbols_file, is_auto_symbol, signed_hex_serde,
            write_splits_file, write_symbols_file, SectionAddressRef,
        },
        dep::DepFile,
        dol::process_dol,
        elf::{process_elf, write_elf},
        file::{
            buf_reader, buf_writer, map_file, map_file_basic, touch, verify_hash, FileIterator,
            FileReadInfo,
        },
        lcf::{asm_path_for_unit, generate_ldscript, obj_path_for_unit},
        map::apply_map_file,
        rel::{process_rel, process_rel_header, update_rel_section_alignment},
        rso::{process_rso, DOL_SECTION_ABS, DOL_SECTION_ETI, DOL_SECTION_NAMES},
        split::{is_linker_generated_object, split_obj, update_splits},
        IntoCow, ToCow,
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
    Config(ConfigArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views DOL file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// DOL file
    pub dol_file: PathBuf,
    #[argp(option, short = 's')]
    /// optional path to selfile.sel
    pub selfile: Option<PathBuf>,
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
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generates a project configuration file from a DOL (& RELs).
#[argp(subcommand, name = "config")]
pub struct ConfigArgs {
    #[argp(positional)]
    /// object files
    objects: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// output config YAML file
    out_file: PathBuf,
}

#[inline]
fn bool_true() -> bool { true }

#[inline]
fn is_true(b: &bool) -> bool { *b }

#[inline]
fn is_default<T>(t: &T) -> bool
where T: Default + PartialEq {
    t == &T::default()
}

mod path_slash_serde {
    use std::path::PathBuf;

    use path_slash::PathBufExt as _;
    use serde::{Deserialize, Deserializer, Serializer};

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
    use serde::{Deserialize, Deserializer, Serializer};

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
        Ok(Option::deserialize(deserializer)?.map(PathBuf::from_slash::<String>))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectConfig {
    #[serde(flatten)]
    pub base: ModuleConfig,
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "is_default")]
    pub selfile: Option<PathBuf>,
    #[serde(skip_serializing_if = "is_default")]
    pub selfile_hash: Option<String>,
    /// Version of the MW `.comment` section format.
    /// If not present, no `.comment` sections will be written.
    #[serde(skip_serializing_if = "is_default")]
    pub mw_comment_version: Option<u8>,
    /// Disables some time-consuming analysis passes.
    /// Useful when the symbols file is already created.
    #[serde(default, skip_serializing_if = "is_default")]
    pub quick_analysis: bool,
    #[serde(default, skip_serializing_if = "is_default")]
    pub modules: Vec<ModuleConfig>,
    // Analysis options
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub detect_objects: bool,
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub detect_strings: bool,
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub write_asm: bool,
    /// Specifies the start of the common BSS section.
    #[serde(skip_serializing_if = "is_default")]
    pub common_start: Option<u32>,
    /// Disables all analysis passes that yield new symbols,
    /// and instead assumes that all symbols are known.
    #[serde(default, skip_serializing_if = "is_default")]
    pub symbols_known: bool,
    /// Fills gaps between symbols to avoid linker realignment.
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub fill_gaps: bool,
    /// Marks all emitted symbols as "exported" to prevent the linker from removing them.
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub export_all: bool,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            base: Default::default(),
            selfile: None,
            selfile_hash: None,
            mw_comment_version: None,
            quick_analysis: false,
            modules: vec![],
            detect_objects: true,
            detect_strings: true,
            write_asm: true,
            common_start: None,
            symbols_known: false,
            fill_gaps: true,
            export_all: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ModuleConfig {
    /// Object name. If not specified, the file name without extension will be used.
    #[serde(skip_serializing_if = "is_default")]
    pub name: Option<String>,
    #[serde(with = "path_slash_serde")]
    pub object: PathBuf,
    #[serde(skip_serializing_if = "is_default")]
    pub hash: Option<String>,
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "is_default")]
    pub splits: Option<PathBuf>,
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "is_default")]
    pub symbols: Option<PathBuf>,
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "is_default")]
    pub map: Option<PathBuf>,
    /// Forces the given symbols to be active (exported) in the linker script.
    #[serde(default, skip_serializing_if = "is_default")]
    pub force_active: Vec<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub ldscript_template: Option<PathBuf>,
    /// Overrides links to other modules.
    #[serde(skip_serializing_if = "is_default")]
    pub links: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extract: Vec<ExtractConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_relocations: Vec<BlockRelocationConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_relocations: Vec<AddRelocationConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExtractConfig {
    /// The name of the symbol to extract.
    pub symbol: String,
    /// If specified, the symbol's data will be extracted to the given file.
    /// Path is relative to `out_dir/bin`.
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<PathBuf>,
    /// If specified, the symbol's data will be extracted to the given file as a C array.
    /// Path is relative to `out_dir/include`.
    #[serde(with = "path_slash_serde_option", default, skip_serializing_if = "Option::is_none")]
    pub header: Option<PathBuf>,
}

/// A relocation that should be blocked.
/// Only one of `source` or `target` should be specified.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlockRelocationConfig {
    /// Match by the address of the relocation.
    /// Format: `section:address`, e.g. `.text:0x80001234`.
    pub source: Option<SectionAddressRef>,
    /// Match by the address of the relocation target.
    /// Format: `section:address`, e.g. `.text:0x80001234`.
    pub target: Option<SectionAddressRef>,
    /// An optional end address for the (exclusive) range.
    /// Format: `section:address`, e.g. `.text:0x80001234`.
    pub end: Option<SectionAddressRef>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AddRelocationConfig {
    /// The address of the relocation to add.
    /// Format: `section:address`, e.g. `.text:0x80001234`.
    pub source: SectionAddressRef,
    /// The relocation type to add.
    #[serde(rename = "type")]
    pub kind: ObjRelocKind,
    /// The target symbol name.
    pub target: String,
    /// The addend for the relocation. (optional)
    #[serde(with = "signed_hex_serde", default, skip_serializing_if = "is_default")]
    pub addend: i64,
}

impl ModuleConfig {
    pub fn file_name(&self) -> Cow<'_, str> {
        self.object.file_name().unwrap_or(self.object.as_os_str()).to_string_lossy()
    }

    pub fn file_prefix(&self) -> Cow<'_, str> {
        match self.file_name() {
            Cow::Borrowed(s) => {
                Cow::Borrowed(s.split_once('.').map(|(prefix, _)| prefix).unwrap_or(s))
            }
            Cow::Owned(s) => {
                Cow::Owned(s.split_once('.').map(|(prefix, _)| prefix).unwrap_or(&s).to_string())
            }
        }
    }

    pub fn name(&self) -> Cow<'_, str> {
        self.name.as_ref().map(|n| n.as_str().to_cow()).unwrap_or_else(|| self.file_prefix())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputUnit {
    #[serde(with = "path_slash_serde")]
    pub object: PathBuf,
    pub name: String,
    pub autogenerated: bool,
    pub code_size: u32,
    pub data_size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputModule {
    pub name: String,
    pub module_id: u32,
    #[serde(with = "path_slash_serde")]
    pub ldscript: PathBuf,
    pub entry: Option<String>,
    pub units: Vec<OutputUnit>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct OutputLink {
    pub modules: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputConfig {
    pub version: String,
    #[serde(flatten)]
    pub base: OutputModule,
    pub modules: Vec<OutputModule>,
    pub links: Vec<OutputLink>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Split(c_args) => split(c_args),
        SubCommand::Diff(c_args) => diff(c_args),
        SubCommand::Apply(c_args) => apply(c_args),
        SubCommand::Config(c_args) => config(c_args),
    }
}

fn apply_selfile(obj: &mut ObjInfo, buf: &[u8]) -> Result<()> {
    let rso = process_rso(&mut Cursor::new(buf))?;
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
            let dol_section_name = if dol_section_index == DOL_SECTION_ETI as usize {
                "extabindex"
            } else {
                DOL_SECTION_NAMES.get(dol_section_index).and_then(|&opt| opt).ok_or_else(|| {
                    anyhow!("Can't add symbol for unknown DOL section {}", dol_section_index)
                })?
            };
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
                flags: ObjSymbolFlagSet(existing_symbol.flags.0 | ObjSymbolFlags::Exported),
                kind: existing_symbol.kind,
                align: existing_symbol.align,
                data_kind: existing_symbol.data_kind,
                name_hash: existing_symbol.name_hash,
                demangled_name_hash: existing_symbol.demangled_name_hash,
            })?;
        } else {
            log::debug!("Creating symbol {} at {:#010X}", symbol.name, address);
            obj.symbols.add(
                ObjSymbol {
                    name: symbol.name.clone(),
                    demangled_name: symbol.demangled_name.clone(),
                    address: address as u64,
                    section,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global | ObjSymbolFlags::Exported),
                    ..*symbol
                },
                false,
            )?;
        }
    }
    Ok(())
}

pub fn info(args: InfoArgs) -> Result<()> {
    let mut obj = {
        let file = map_file(&args.dol_file)?;
        process_dol(file.as_slice(), "")?
    };
    apply_signatures(&mut obj)?;

    let mut state = AnalyzerState::default();
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.detect_functions(&obj)?;
    log::debug!(
        "Discovered {} functions",
        state.functions.iter().filter(|(_, i)| i.end.is_some()).count()
    );

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    apply_signatures_post(&mut obj)?;

    if let Some(selfile) = &args.selfile {
        let file = map_file(selfile)?;
        apply_selfile(&mut obj, file.as_slice())?;
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
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Section", "Address", "Size", "Name");
    for (_, symbol) in obj.symbols.iter_ordered().chain(obj.symbols.iter_abs()) {
        if symbol.name.starts_with('@') || is_auto_symbol(symbol) {
            continue;
        }
        let section_str = if let Some(section) = symbol.section {
            obj.sections[section].name.as_str()
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
            "\t{: >10} | {: <#10X} | {: <10} | {: <10}",
            section_str, symbol.address, size_str, symbol.name
        );
    }
    println!("\n{} discovered functions from exception table", obj.known_functions.len());
    Ok(())
}

struct ModuleInfo<'a> {
    obj: ObjInfo,
    config: &'a ModuleConfig,
    symbols_cache: Option<FileReadInfo>,
    splits_cache: Option<FileReadInfo>,
}

type ModuleMapByName<'a> = BTreeMap<String, ModuleInfo<'a>>;
type ModuleMapById<'a> = BTreeMap<u32, &'a ModuleInfo<'a>>;

fn update_symbols(
    obj: &mut ObjInfo,
    modules: &[&ModuleInfo<'_>],
    create_symbols: bool,
) -> Result<()> {
    log::debug!("Updating symbols for module {}", obj.module_id);

    // Find all references to this module from other modules
    for (source_module_id, rel_reloc) in obj
        .unresolved_relocations
        .iter()
        .map(|r| (obj.module_id, r))
        .chain(modules.iter().flat_map(|info| {
            info.obj.unresolved_relocations.iter().map(|r| (info.obj.module_id, r))
        }))
        .filter(|(_, r)| r.module_id == obj.module_id)
    {
        if source_module_id == obj.module_id {
            // Skip if already resolved
            let (_, source_section) =
                obj.sections.get_elf_index(rel_reloc.section as usize).ok_or_else(|| {
                    anyhow!(
                        "Failed to locate REL section {} in module ID {}: source module {}, {:?}",
                        rel_reloc.section,
                        obj.module_id,
                        source_module_id,
                        rel_reloc
                    )
                })?;
            if source_section.relocations.contains(rel_reloc.address) {
                continue;
            }
        }

        let (target_section_index, target_section) =
            obj.sections.get_elf_index(rel_reloc.target_section as usize).ok_or_else(|| {
                anyhow!(
                    "Failed to locate REL section {} in module ID {}: source module {}, {:?}",
                    rel_reloc.target_section,
                    obj.module_id,
                    source_module_id,
                    rel_reloc
                )
            })?;

        if let Some((symbol_index, symbol)) = obj.symbols.for_relocation(
            SectionAddress::new(target_section_index, rel_reloc.addend),
            rel_reloc.kind,
        )? {
            // Update symbol
            log::trace!(
                "Found symbol in section {} at {:#010X}: {}",
                rel_reloc.target_section,
                rel_reloc.addend,
                symbol.name
            );
            obj.symbols.flags(symbol_index).set_force_active(true);
        } else if create_symbols {
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
                address: rel_reloc.addend as u64,
                section: Some(target_section_index),
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Exported.into()),
                ..Default::default()
            })?;
        }
    }

    Ok(())
}

fn create_relocations(
    obj: &mut ObjInfo,
    modules: &ModuleMapById<'_>,
    dol_obj: &ObjInfo,
) -> Result<()> {
    log::debug!("Creating relocations for module {}", obj.module_id);

    // Resolve all relocations in this module
    for rel_reloc in take(&mut obj.unresolved_relocations) {
        // Skip if already resolved
        let (_, source_section) =
            obj.sections.get_elf_index(rel_reloc.section as usize).ok_or_else(|| {
                anyhow!(
                    "Failed to locate REL section {} in module ID {}: {:?}",
                    rel_reloc.section,
                    obj.module_id,
                    rel_reloc
                )
            })?;
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
                .obj
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

        let Some((symbol_index, symbol)) = target_obj.symbols.for_relocation(
            SectionAddress::new(target_section_index, rel_reloc.addend),
            rel_reloc.kind,
        )?
        else {
            bail!(
                "Couldn't find module {} ({}) symbol in section {} at {:#010X}",
                rel_reloc.module_id,
                target_obj.name,
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
        let (_, source_section) =
            obj.sections.get_elf_index_mut(rel_reloc.section as usize).unwrap();
        source_section.relocations.insert(rel_reloc.address, reloc)?;
    }

    Ok(())
}

fn resolve_external_relocations(
    obj: &mut ObjInfo,
    modules: &ModuleMapById<'_>,
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
                                .obj
                        };

                        let target_symbol = &target_obj.symbols[reloc.target_symbol];
                        let symbol_idx = obj.symbols.add_direct(ObjSymbol {
                            name: target_symbol.name.clone(),
                            demangled_name: target_symbol.demangled_name.clone(),
                            ..Default::default()
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

struct AnalyzeResult {
    obj: ObjInfo,
    dep: Vec<PathBuf>,
    symbols_cache: Option<FileReadInfo>,
    splits_cache: Option<FileReadInfo>,
}

fn load_analyze_dol(config: &ProjectConfig) -> Result<AnalyzeResult> {
    log::debug!("Loading {}", config.base.object.display());
    let mut obj = {
        let file = map_file(&config.base.object)?;
        if let Some(hash_str) = &config.base.hash {
            verify_hash(file.as_slice(), hash_str)?;
        }
        process_dol(file.as_slice(), config.base.name().as_ref())?
    };
    let mut dep = vec![config.base.object.clone()];

    if let Some(comment_version) = config.mw_comment_version {
        obj.mw_comment = Some(MWComment::new(comment_version)?);
    }

    if let Some(map_path) = &config.base.map {
        apply_map_file(map_path, &mut obj, config.common_start, config.mw_comment_version)?;
        dep.push(map_path.clone());
    }

    let splits_cache = if let Some(splits_path) = &config.base.splits {
        dep.push(splits_path.clone());
        apply_splits_file(splits_path, &mut obj)?
    } else {
        None
    };

    let symbols_cache = if let Some(symbols_path) = &config.base.symbols {
        dep.push(symbols_path.clone());
        apply_symbols_file(symbols_path, &mut obj)?
    } else {
        None
    };

    // Apply block relocations from config
    apply_block_relocations(&mut obj, &config.base.block_relocations)?;

    if !config.symbols_known {
        // TODO move before symbols?
        debug!("Performing signature analysis");
        apply_signatures(&mut obj)?;

        if !config.quick_analysis {
            let mut state = AnalyzerState::default();
            debug!("Detecting function boundaries");
            FindSaveRestSleds::execute(&mut state, &obj)?;
            state.detect_functions(&obj)?;
            FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
            state.apply(&mut obj)?;
        }

        apply_signatures_post(&mut obj)?;
    }

    if let Some(selfile) = &config.selfile {
        log::info!("Loading {}", selfile.display());
        let file = map_file(selfile)?;
        if let Some(hash) = &config.selfile_hash {
            verify_hash(file.as_slice(), hash)?;
        }
        apply_selfile(&mut obj, file.as_slice())?;
        dep.push(selfile.clone());
    }

    // Create _ctors and _dtors symbols if missing
    update_ctors_dtors(&mut obj)?;

    // Apply additional relocations from config
    apply_add_relocations(&mut obj, &config.base.add_relocations)?;

    Ok(AnalyzeResult { obj, dep, symbols_cache, splits_cache })
}

fn split_write_obj(
    module: &mut ModuleInfo,
    config: &ProjectConfig,
    base_dir: &Path,
    out_dir: &Path,
    no_update: bool,
) -> Result<OutputModule> {
    debug!("Performing relocation analysis");
    let mut tracker = Tracker::new(&module.obj);
    tracker.process(&module.obj)?;

    debug!("Applying relocations");
    tracker.apply(&mut module.obj, false)?;

    if !config.symbols_known && config.detect_objects {
        debug!("Detecting object boundaries");
        detect_objects(&mut module.obj)?;
    }

    if config.detect_strings {
        debug!("Detecting strings");
        detect_strings(&mut module.obj)?;
    }

    debug!("Adjusting splits");
    let module_id = module.obj.module_id;
    update_splits(
        &mut module.obj,
        if module_id == 0 { config.common_start } else { None },
        config.fill_gaps,
    )?;

    if !no_update {
        debug!("Writing configuration");
        if let Some(symbols_path) = &module.config.symbols {
            write_symbols_file(symbols_path, &module.obj, module.symbols_cache)?;
        }
        if let Some(splits_path) = &module.config.splits {
            write_splits_file(splits_path, &module.obj, false, module.splits_cache)?;
        }
    }

    debug!("Splitting {} objects", module.obj.link_order.len());
    let module_name = module.config.name().to_string();
    let split_objs = split_obj(&module.obj, Some(module_name.as_str()))?;

    debug!("Writing object files");
    DirBuilder::new()
        .recursive(true)
        .create(out_dir)
        .with_context(|| format!("Failed to create out dir '{}'", out_dir.display()))?;
    let obj_dir = out_dir.join("obj");
    let entry = if module.obj.kind == ObjKind::Executable {
        module.obj.entry.and_then(|e| {
            let (section_index, _) = module.obj.sections.at_address(e as u32).ok()?;
            let symbols =
                module.obj.symbols.at_section_address(section_index, e as u32).collect_vec();
            best_match_for_reloc(symbols, ObjRelocKind::PpcRel24).map(|(_, s)| s.name.clone())
        })
    } else {
        module.obj.symbols.by_name("_prolog")?.map(|(_, s)| s.name.clone())
    };
    let mut out_config = OutputModule {
        name: module_name,
        module_id,
        ldscript: out_dir.join("ldscript.lcf"),
        units: Vec::with_capacity(split_objs.len()),
        entry,
    };
    for (unit, split_obj) in module.obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj, config.export_all)?;
        let out_path = obj_dir.join(obj_path_for_unit(&unit.name));
        out_config.units.push(OutputUnit {
            object: out_path.clone(),
            name: unit.name.clone(),
            autogenerated: unit.autogenerated,
            code_size: split_obj.code_size(),
            data_size: split_obj.data_size(),
        });
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        write_if_changed(&out_path, &out_obj)?;
    }

    // Write extracted files
    for extract in &module.config.extract {
        let (_, symbol) = module
            .obj
            .symbols
            .by_name(&extract.symbol)?
            .with_context(|| format!("Failed to locate symbol '{}'", extract.symbol))?;
        let section_index = symbol
            .section
            .with_context(|| format!("Symbol '{}' has no section", extract.symbol))?;
        let section = &module.obj.sections[section_index];
        let data = section.symbol_data(symbol)?;

        if let Some(binary) = &extract.binary {
            let out_path = base_dir.join("bin").join(binary);
            if let Some(parent) = out_path.parent() {
                DirBuilder::new().recursive(true).create(parent)?;
            }
            write_if_changed(&out_path, data)?;
        }

        if let Some(header) = &extract.header {
            let header_string = bin2c(symbol, section, data);
            let out_path = base_dir.join("include").join(header);
            if let Some(parent) = out_path.parent() {
                DirBuilder::new().recursive(true).create(parent)?;
            }
            write_if_changed(&out_path, header_string.as_bytes())?;
        }
    }

    // Generate ldscript.lcf
    let ldscript_template = if let Some(template) = &module.config.ldscript_template {
        Some(fs::read_to_string(template).with_context(|| {
            format!("Failed to read linker script template '{}'", template.display())
        })?)
    } else {
        None
    };
    let ldscript_string =
        generate_ldscript(&module.obj, ldscript_template.as_deref(), &module.config.force_active)?;
    write_if_changed(&out_config.ldscript, ldscript_string.as_bytes())?;

    if config.write_asm {
        debug!("Writing disassembly");
        let asm_dir = out_dir.join("asm");
        for (unit, split_obj) in module.obj.link_order.iter().zip(&split_objs) {
            let out_path = asm_dir.join(asm_path_for_unit(&unit.name));

            let mut w = buf_writer(&out_path)?;
            write_asm(&mut w, split_obj)
                .with_context(|| format!("Failed to write {}", out_path.display()))?;
            w.flush()?;
        }
    }
    Ok(out_config)
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    if path.is_file() {
        let old_file = map_file_basic(path)?;
        // If the file is the same size, check if the contents are the same
        // Avoid writing if unchanged, since it will update the file's mtime
        if old_file.len() == contents.len() as u64
            && xxh3_64(old_file.as_slice()) == xxh3_64(contents)
        {
            return Ok(());
        }
    }
    fs::write(path, contents)
        .with_context(|| format!("Failed to write file '{}'", path.display()))?;
    Ok(())
}

fn load_analyze_rel(config: &ProjectConfig, module_config: &ModuleConfig) -> Result<AnalyzeResult> {
    debug!("Loading {}", module_config.object.display());
    let file = map_file(&module_config.object)?;
    if let Some(hash_str) = &module_config.hash {
        verify_hash(file.as_slice(), hash_str)?;
    }
    let (header, mut module_obj) =
        process_rel(&mut Cursor::new(file.as_slice()), module_config.name().as_ref())?;

    if let Some(comment_version) = config.mw_comment_version {
        module_obj.mw_comment = Some(MWComment::new(comment_version)?);
    }

    let mut dep = vec![module_config.object.clone()];
    if let Some(map_path) = &module_config.map {
        apply_map_file(map_path, &mut module_obj, None, None)?;
        dep.push(map_path.clone());
    }

    let splits_cache = if let Some(splits_path) = &module_config.splits {
        dep.push(splits_path.clone());
        apply_splits_file(splits_path, &mut module_obj)?
    } else {
        None
    };

    let symbols_cache = if let Some(symbols_path) = &module_config.symbols {
        dep.push(symbols_path.clone());
        apply_symbols_file(symbols_path, &mut module_obj)?
    } else {
        None
    };

    // Apply block relocations from config
    apply_block_relocations(&mut module_obj, &module_config.block_relocations)?;

    if !config.symbols_known {
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
    }

    // Create _ctors and _dtors symbols if missing
    update_ctors_dtors(&mut module_obj)?;

    // Determine REL section alignment
    update_rel_section_alignment(&mut module_obj, &header)?;

    // Apply additional relocations from config
    apply_add_relocations(&mut module_obj, &module_config.add_relocations)?;

    Ok(AnalyzeResult { obj: module_obj, dep, symbols_cache, splits_cache })
}

fn split(args: SplitArgs) -> Result<()> {
    if let Some(jobs) = args.jobs {
        rayon::ThreadPoolBuilder::new().num_threads(jobs).build_global().unwrap();
    }

    let command_start = Instant::now();
    info!("Loading {}", args.config.display());
    let mut config: ProjectConfig = {
        let mut config_file = buf_reader(&args.config)?;
        serde_yaml::from_reader(&mut config_file)?
    };

    for module_config in config.modules.iter_mut() {
        let file = map_file(&module_config.object)?;
        if let Some(hash_str) = &module_config.hash {
            verify_hash(file.as_slice(), hash_str)?;
        } else {
            module_config.hash = Some(file_sha1_string(&mut file.as_reader())?);
        }
    }

    let out_config_path = args.out_dir.join("config.json");
    let mut dep = DepFile::new(out_config_path.clone());

    let module_count = config.modules.len() + 1;
    let num_threads = min(rayon::current_num_threads(), module_count);
    info!(
        "Loading and analyzing {} module{} (using {} thread{})",
        module_count,
        if module_count == 1 { "" } else { "s" },
        num_threads,
        if num_threads == 1 { "" } else { "s" }
    );
    let mut dol_result: Option<Result<AnalyzeResult>> = None;
    let mut modules_result: Option<Result<Vec<AnalyzeResult>>> = None;
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
    let mut dol = {
        let result = dol_result.unwrap()?;
        dep.extend(result.dep);
        ModuleInfo {
            obj: result.obj,
            config: &config.base,
            symbols_cache: result.symbols_cache,
            splits_cache: result.splits_cache,
        }
    };
    let mut function_count = dol.obj.symbols.by_kind(ObjSymbolKind::Function).count();

    let mut modules = ModuleMapByName::new();
    for (idx, result) in modules_result.unwrap()?.into_iter().enumerate() {
        function_count += result.obj.symbols.by_kind(ObjSymbolKind::Function).count();
        dep.extend(result.dep);
        match modules.entry(result.obj.name.clone()) {
            Entry::Vacant(e) => e.insert(ModuleInfo {
                obj: result.obj,
                config: &config.modules[idx],
                symbols_cache: result.symbols_cache,
                splits_cache: result.splits_cache,
            }),
            Entry::Occupied(_) => bail!("Duplicate module name {}", result.obj.name),
        };
    }
    info!(
        "Initial analysis completed in {}.{:03}s (found {} functions)",
        duration.as_secs(),
        duration.subsec_millis(),
        function_count
    );

    fn get_links<'a>(
        module: &ModuleInfo<'_>,
        modules: &'a ModuleMapByName<'a>,
    ) -> Result<Vec<&'a ModuleInfo<'a>>> {
        if let Some(links) = &module.config.links {
            // Link to specified modules
            links
                .iter()
                .map(|n| modules.get(n))
                .collect::<Option<Vec<_>>>()
                .with_context(|| format!("Failed to resolve links for module {}", module.obj.name))
        } else {
            // Link to all other modules
            Ok(modules.values().collect())
        }
    }

    fn get_links_map<'a>(
        module: &ModuleInfo<'_>,
        modules: &'a ModuleMapByName<'a>,
    ) -> Result<ModuleMapById<'a>> {
        let links = get_links(module, modules)?;
        let mut map = ModuleMapById::new();
        for link in links {
            match map.entry(link.obj.module_id) {
                Entry::Vacant(e) => {
                    e.insert(link);
                }
                Entry::Occupied(_) => bail!(
                    "Duplicate module ID {} in links for module {} (ID {}).\n\
                    This likely means you need to specify the links manually.",
                    link.obj.module_id,
                    module.obj.name,
                    module.obj.module_id
                ),
            }
        }
        Ok(map)
    }

    if !modules.is_empty() {
        let module_names = modules.keys().cloned().collect_vec();

        // Create any missing symbols (referenced from other modules) and set FORCEACTIVE
        update_symbols(&mut dol.obj, &modules.values().collect::<Vec<_>>(), !config.symbols_known)?;
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links(&module, &modules)?;
            update_symbols(&mut module.obj, &links, !config.symbols_known)?;
            modules.insert(module_name.clone(), module);
        }

        // Create relocations to symbols in other modules
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links_map(&module, &modules)?;
            create_relocations(&mut module.obj, &links, &dol.obj)?;
            modules.insert(module_name.clone(), module);
        }

        // Replace external relocations with internal ones, creating extern symbols
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links_map(&module, &modules)?;
            resolve_external_relocations(&mut module.obj, &links, Some(&dol.obj))?;
            modules.insert(module_name.clone(), module);
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
                info_span!("module", name = %config.base.name(), id = dol.obj.module_id).entered();
            dol_result = Some(
                split_write_obj(&mut dol, &config, &args.out_dir, &args.out_dir, args.no_update)
                    .with_context(|| {
                        format!(
                            "While processing object '{}' (module ID {})",
                            config.base.file_name(),
                            dol.obj.module_id
                        )
                    }),
            );
        });
        // Modules
        s.spawn(|_| {
            modules_result = Some(
                modules
                    .par_iter_mut()
                    .map(|(module_name, module)| {
                        let _span =
                            info_span!("module", name = %module.config.name(), id = module.obj.module_id)
                                .entered();
                        let out_dir = args.out_dir.join(module.config.name().as_ref());
                        split_write_obj(module, &config, &args.out_dir, &out_dir, args.no_update).with_context(
                            || {
                                format!(
                                    "While processing object '{}' (module {} ID {})",
                                    module.config.file_name(),
                                    module_name,
                                    module.obj.module_id
                                )
                            },
                        )
                    })
                    .collect(),
            );
        });
    });
    let duration = start.elapsed();
    let mut modules_config = modules_result.unwrap()?;
    modules_config.sort_by(|a, b| {
        // Sort by module ID, then name
        a.module_id.cmp(&b.module_id).then(a.name.cmp(&b.name))
    });
    let mut out_config = OutputConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        base: dol_result.unwrap()?,
        modules: modules_config,
        links: vec![],
    };
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

    // Generate links
    for module_info in modules.values() {
        let mut links = get_links_map(module_info, &modules)?;
        links.insert(0, &dol);
        links.insert(module_info.obj.module_id, module_info);
        let names = links.values().map(|m| m.obj.name.clone()).collect_vec();
        let output_link = OutputLink { modules: names };
        if !out_config.links.contains(&output_link) {
            out_config.links.push(output_link);
        }
    }

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
    info!("Total time: {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    Ok(())
}

#[allow(dead_code)]
fn validate<P>(obj: &ObjInfo, elf_file: P, state: &AnalyzerState) -> Result<()>
where P: AsRef<Path> {
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
            match state.functions.get(&symbol_addr) {
                Some(info) => {
                    if let Some(end) = info.end {
                        if symbol.size > 0 && end != (symbol_addr + symbol.size as u32) {
                            log::warn!(
                                "Function {:#010X} ({}) ends at {:#010X}, expected {:#010X}",
                                symbol.address,
                                symbol.name,
                                end,
                                symbol.address + symbol.size
                            );
                        }
                    } else {
                        log::warn!(
                            "Function {:#010X} ({}) has no end",
                            symbol.address,
                            symbol.name
                        );
                    }
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
    for (&start, info) in &state.functions {
        let Some(end) = info.end else {
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
    let mut config_file = buf_reader(&args.config)?;
    let config: ProjectConfig = serde_yaml::from_reader(&mut config_file)?;

    log::info!("Loading {}", config.base.object.display());
    let mut obj = {
        let file = map_file(&config.base.object)?;
        if let Some(hash_str) = &config.base.hash {
            verify_hash(file.as_slice(), hash_str)?;
        }
        process_dol(file.as_slice(), config.base.name().as_ref())?
    };

    if let Some(symbols_path) = &config.base.symbols {
        apply_symbols_file(symbols_path, &mut obj)?;
    }

    log::info!("Loading {}", args.elf_file.display());
    let linked_obj = process_elf(&args.elf_file)?;

    let common_bss = obj.sections.common_bss_start();
    for orig_sym in obj.symbols.iter().filter(|s| {
        !matches!(s.kind, ObjSymbolKind::Unknown | ObjSymbolKind::Section) && !s.flags.is_stripped()
    }) {
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
                if linked_sym.size != orig_sym.size &&
                    // TODO validate common symbol sizes
                    // (need to account for inflation bug)
                    matches!(common_bss, Some((idx, addr)) if
                        orig_section_index == idx && orig_sym.address as u32 >= addr)
                {
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
            std::process::exit(1);
        }
    }

    // Data diff
    for orig_sym in obj.symbols.iter().filter(|s| {
        s.size > 0 && !matches!(s.kind, ObjSymbolKind::Unknown | ObjSymbolKind::Section)
    }) {
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
            log::error!("Original: {}", hex::encode_upper(orig_data));
            log::error!("Linked:   {}", hex::encode_upper(linked_data));
            std::process::exit(1);
        }
    }

    log::info!("OK");
    Ok(())
}

fn apply(args: ApplyArgs) -> Result<()> {
    log::info!("Loading {}", args.config.display());
    let mut config_file = buf_reader(&args.config)?;
    let config: ProjectConfig = serde_yaml::from_reader(&mut config_file)?;

    log::info!("Loading {}", config.base.object.display());
    let mut obj = {
        let file = map_file(&config.base.object)?;
        if let Some(hash_str) = &config.base.hash {
            verify_hash(file.as_slice(), hash_str)?;
        }
        process_dol(file.as_slice(), config.base.name().as_ref())?
    };

    let Some(symbols_path) = &config.base.symbols else {
        bail!("No symbols file specified in config");
    };
    let Some(symbols_cache) = apply_symbols_file(symbols_path, &mut obj)? else {
        bail!("Symbols file '{}' does not exist", symbols_path.display());
    };

    log::info!("Loading {}", args.elf_file.display());
    let linked_obj = process_elf(&args.elf_file)?;

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
                updated_sym.name.clone_from(&linked_sym.name);
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
                // Don't overwrite unknown scope with global
                && (linked_scope != ObjSymbolScope::Global
                    || orig_sym.flags.scope() != ObjSymbolScope::Unknown)
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
            || is_auto_symbol(linked_sym)
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
                name_hash: linked_sym.name_hash,
                demangled_name_hash: linked_sym.demangled_name_hash,
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

    write_symbols_file(config.base.symbols.as_ref().unwrap(), &obj, Some(symbols_cache))?;

    Ok(())
}

fn config(args: ConfigArgs) -> Result<()> {
    let mut config = ProjectConfig::default();
    let mut modules = Vec::<(u32, ModuleConfig)>::new();
    for result in FileIterator::new(&args.objects)? {
        let (path, entry) = result?;
        log::info!("Loading {}", path.display());

        match path.extension() {
            Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("dol")) => {
                config.base.object = path;
                config.base.hash = Some(file_sha1_string(&mut entry.as_reader())?);
            }
            Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("rel")) => {
                let header = process_rel_header(&mut entry.as_reader())?;
                modules.push((header.module_id, ModuleConfig {
                    object: path,
                    hash: Some(file_sha1_string(&mut entry.as_reader())?),
                    ..Default::default()
                }));
            }
            Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("sel")) => {
                config.selfile = Some(path);
                config.selfile_hash = Some(file_sha1_string(&mut entry.as_reader())?);
            }
            Some(ext) if ext.eq_ignore_ascii_case(OsStr::new("rso")) => {
                config.modules.push(ModuleConfig {
                    object: path,
                    hash: Some(file_sha1_string(&mut entry.as_reader())?),
                    ..Default::default()
                });
            }
            _ => bail!("Unknown file extension: '{}'", path.display()),
        }
    }
    modules.sort_by(|(a_id, a_config), (b_id, b_config)| {
        // Sort by module ID, then by name
        a_id.cmp(b_id).then(a_config.name().cmp(&b_config.name()))
    });
    config.modules.extend(modules.into_iter().map(|(_, m)| m));

    let mut out = buf_writer(&args.out_file)?;
    serde_yaml::to_writer(&mut out, &config)?;
    out.flush()?;
    Ok(())
}

/// Applies the blocked relocation ranges from module config `blocked_relocations`
fn apply_block_relocations(
    obj: &mut ObjInfo,
    block_relocations: &[BlockRelocationConfig],
) -> Result<()> {
    for reloc in block_relocations {
        let end = reloc.end.as_ref().map(|end| end.resolve(obj)).transpose()?;
        match (&reloc.source, &reloc.target) {
            (Some(_), Some(_)) => {
                bail!("Cannot specify both source and target for blocked relocation");
            }
            (Some(source), None) => {
                let start = source.resolve(obj)?;
                obj.blocked_relocation_sources.insert(start, end.unwrap_or(start + 1));
            }
            (None, Some(target)) => {
                let start = target.resolve(obj)?;
                obj.blocked_relocation_targets.insert(start, end.unwrap_or(start + 1));
            }
            (None, None) => {
                bail!("Blocked relocation must specify either source or target");
            }
        }
    }
    Ok(())
}

/// Applies the relocations from module config `add_relocations`.
fn apply_add_relocations(obj: &mut ObjInfo, relocations: &[AddRelocationConfig]) -> Result<()> {
    for reloc in relocations {
        let SectionAddress { section, address } = reloc.source.resolve(obj)?;
        let (target_symbol, _) = match obj.symbols.by_name(&reloc.target)? {
            Some(v) => v,
            None => {
                // Assume external symbol
                let symbol_index = obj.symbols.add_direct(ObjSymbol {
                    name: reloc.target.clone(),
                    demangled_name: demangle(&reloc.target, &Default::default()),
                    ..Default::default()
                })?;
                (symbol_index, &obj.symbols[symbol_index])
            }
        };
        obj.sections[section].relocations.replace(address, ObjReloc {
            kind: reloc.kind,
            target_symbol,
            addend: reloc.addend,
            module: None,
        });
    }
    Ok(())
}
