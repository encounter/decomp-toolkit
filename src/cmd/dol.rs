use std::{
    cmp::min,
    collections::{btree_map::Entry, hash_map, BTreeMap, HashMap},
    fs,
    fs::DirBuilder,
    io::{Cursor, Seek, Write},
    mem::take,
    str::FromStr,
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use cwdemangle::demangle;
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span};
use typed_path::{Utf8NativePath, Utf8NativePathBuf, Utf8UnixPath, Utf8UnixPathBuf};
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
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope, SectionIndex, SymbolIndex,
    },
    util::{
        asm::write_asm,
        bin2c::{bin2c, HeaderKind},
        comment::MWComment,
        config::{
            apply_splits_file, apply_symbols_file, is_auto_symbol, signed_hex_serde,
            write_splits_file, write_symbols_file, SectionAddressRef,
        },
        dep::DepFile,
        diff::{calc_diff_ranges, print_diff, process_code},
        dol::process_dol,
        elf::{process_elf, write_elf},
        extab::clean_extab,
        file::{
            buf_copy_with_hash, buf_writer, check_hash_str, touch, verify_hash, FileIterator,
            FileReadInfo,
        },
        lcf::{asm_path_for_unit, generate_ldscript, obj_path_for_unit},
        map::apply_map_file,
        path::{check_path_buf, native_path},
        rel::{process_rel, process_rel_header, update_rel_section_alignment},
        rso::{process_rso, DOL_SECTION_ABS, DOL_SECTION_ETI, DOL_SECTION_NAMES},
        split::{is_linker_generated_object, split_obj, update_splits},
        IntoCow, ToCow,
    },
    vfs::{detect, open_file, open_file_with_fs, open_fs, ArchiveKind, FileFormat, Vfs, VfsFile},
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
    #[argp(positional, from_str_fn(native_path))]
    /// DOL file
    pub dol_file: Utf8NativePathBuf,
    #[argp(option, short = 's', from_str_fn(native_path))]
    /// optional path to selfile.sel
    pub selfile: Option<Utf8NativePathBuf>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits a DOL into relocatable objects.
#[argp(subcommand, name = "split")]
pub struct SplitArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input configuration file
    config: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output directory
    out_dir: Utf8NativePathBuf,
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
    #[argp(positional, from_str_fn(native_path))]
    /// input configuration file
    config: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// linked ELF
    elf_file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Applies updated symbols from a linked ELF to the project configuration.
#[argp(subcommand, name = "apply")]
pub struct ApplyArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input configuration file
    config: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// linked ELF
    elf_file: Utf8NativePathBuf,
    #[argp(switch)]
    /// always update anonymous local symbol names, even if they are similar
    full: bool,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generates a project configuration file from a DOL (& RELs).
#[argp(subcommand, name = "config")]
pub struct ConfigArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// object files
    objects: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// output config YAML file
    out_file: Utf8NativePathBuf,
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

mod unix_path_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use typed_path::Utf8UnixPathBuf;

    pub fn serialize<S>(path: &Utf8UnixPathBuf, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_str(path.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Utf8UnixPathBuf, D::Error>
    where D: Deserializer<'de> {
        String::deserialize(deserializer).map(Utf8UnixPathBuf::from)
    }
}

mod unix_path_serde_option {
    use serde::{Deserialize, Deserializer, Serializer};
    use typed_path::Utf8UnixPathBuf;

    pub fn serialize<S>(path: &Option<Utf8UnixPathBuf>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if let Some(path) = path {
            s.serialize_str(path.as_str())
        } else {
            s.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Utf8UnixPathBuf>, D::Error>
    where D: Deserializer<'de> {
        Ok(Option::<String>::deserialize(deserializer)?.map(Utf8UnixPathBuf::from))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectConfig {
    #[serde(flatten)]
    pub base: ModuleConfig,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub selfile: Option<Utf8UnixPathBuf>,
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
    /// Optional base path for all object files.
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub object_base: Option<Utf8UnixPathBuf>,
    /// Whether to extract objects from a disc image into object base. If false, the files
    /// will be used from the disc image directly without extraction.
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub extract_objects: bool,
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
            object_base: None,
            extract_objects: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ModuleConfig {
    /// Object name. If not specified, the file name without extension will be used.
    #[serde(skip_serializing_if = "is_default")]
    pub name: Option<String>,
    #[serde(with = "unix_path_serde")]
    pub object: Utf8UnixPathBuf,
    #[serde(skip_serializing_if = "is_default")]
    pub hash: Option<String>,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub splits: Option<Utf8UnixPathBuf>,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub symbols: Option<Utf8UnixPathBuf>,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub map: Option<Utf8UnixPathBuf>,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub pdb: Option<Utf8UnixPathBuf>,
    /// Forces the given symbols to be active (exported) in the linker script.
    #[serde(default, skip_serializing_if = "is_default")]
    pub force_active: Vec<String>,
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "is_default")]
    pub ldscript_template: Option<Utf8UnixPathBuf>,
    /// Overrides links to other modules.
    #[serde(skip_serializing_if = "is_default")]
    pub links: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extract: Vec<ExtractConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_relocations: Vec<BlockRelocationConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_relocations: Vec<AddRelocationConfig>,
    /// Process exception tables and zero out uninitialized data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_extab: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExtractConfig {
    /// The name of the symbol to extract.
    pub symbol: String,
    /// Optionally rename the output symbol. (e.g. symbol$1234 -> symbol)
    pub rename: Option<String>,
    /// If specified, the symbol's data will be extracted to the given file.
    /// Path is relative to `out_dir/bin`.
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<Utf8UnixPathBuf>,
    /// If specified, the symbol's data will be extracted to the given file as a C array.
    /// Path is relative to `out_dir/include`.
    #[serde(with = "unix_path_serde_option", default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Utf8UnixPathBuf>,
    /// The type for the extracted symbol in the header file. By default, the header will emit
    /// a full symbol declaration (a.k.a. `symbol`), but this can be set to `raw` to emit the raw
    /// data as a byte array. `none` avoids emitting a header entirely, in which case the `header`
    /// field can be used by external asset processing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// A user-defined type for use with external asset processing. This value is simply passed
    /// through to the `custom_type` field in the output config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_type: Option<String>,
    /// User-defined data for use with external asset processing. This value is simply passed
    /// through to the `custom_data` field in the output config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<serde_json::Value>,
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
    pub fn file_name(&self) -> &str { self.object.file_name().unwrap_or(self.object.as_str()) }

    pub fn file_prefix(&self) -> &str {
        let file_name = self.file_name();
        file_name.split_once('.').map(|(prefix, _)| prefix).unwrap_or(file_name)
    }

    pub fn name(&self) -> &str { self.name.as_deref().unwrap_or_else(|| self.file_prefix()) }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputUnit {
    #[serde(with = "unix_path_serde")]
    pub object: Utf8UnixPathBuf,
    pub name: String,
    pub autogenerated: bool,
    pub code_size: u32,
    pub data_size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputModule {
    pub name: String,
    pub module_id: u32,
    #[serde(with = "unix_path_serde")]
    pub ldscript: Utf8UnixPathBuf,
    pub entry: Option<String>,
    pub units: Vec<OutputUnit>,
    pub extract: Vec<OutputExtract>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OutputExtract {
    pub symbol: String,
    pub rename: Option<String>,
    #[serde(with = "unix_path_serde_option")]
    pub binary: Option<Utf8UnixPathBuf>,
    #[serde(with = "unix_path_serde_option")]
    pub header: Option<Utf8UnixPathBuf>,
    pub header_type: String,
    pub custom_type: Option<String>,
    pub custom_data: Option<serde_json::Value>,
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
    for (_, symbol) in rso.symbols.iter() {
        let dol_section_index = match symbol.section {
            Some(section) => section,
            None => bail!(
                "Expected section for symbol '{}' @ {:#010X} in selfile",
                symbol.name,
                symbol.address
            ),
        };
        let (section, address, section_kind) = if dol_section_index
            == DOL_SECTION_ABS as SectionIndex
        {
            (None, symbol.address as u32, None)
        } else {
            let dol_section_name = if dol_section_index == DOL_SECTION_ETI as SectionIndex {
                "extabindex"
            } else {
                DOL_SECTION_NAMES.get(dol_section_index as usize).and_then(|&opt| opt).ok_or_else(
                    || anyhow!("Can't add symbol for unknown DOL section {}", dol_section_index),
                )?
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
        let mut file = open_file(&args.dol_file, true)?;
        process_dol(file.map()?, "")?
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
        let mut file = open_file(selfile, true)?;
        apply_selfile(&mut obj, file.map()?)?;
    }

    println!("{}:", obj.name);
    if let Some(entry) = obj.entry {
        println!("Entry point: {entry:#010X}");
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
    dep: Vec<Utf8NativePathBuf>,
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
                obj.sections.get_elf_index(rel_reloc.section as SectionIndex).ok_or_else(|| {
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

        let (target_section_index, target_section) = obj
            .sections
            .get_elf_index(rel_reloc.target_section as SectionIndex)
            .ok_or_else(|| {
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
            obj.sections.get_elf_index(rel_reloc.section as SectionIndex).ok_or_else(|| {
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
            target_obj.sections.at_address(rel_reloc.addend).map_err(|_| {
                anyhow!("Failed to locate DOL section at {:#010X}", rel_reloc.addend)
            })?
        } else {
            target_obj.sections.get_elf_index(rel_reloc.target_section as SectionIndex).ok_or_else(
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
            obj.sections.get_elf_index_mut(rel_reloc.section as SectionIndex).unwrap();
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
    let mut reloc_to_symbol = HashMap::<RelocRef, SymbolIndex>::new();

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
    dep: Vec<Utf8NativePathBuf>,
    symbols_cache: Option<FileReadInfo>,
    splits_cache: Option<FileReadInfo>,
}

fn load_dol_module(
    config: &ModuleConfig,
    object_base: &ObjectBase,
) -> Result<(ObjInfo, Utf8NativePathBuf)> {
    let object_path = object_base.join(&config.object);
    log::debug!("Loading {}", object_path);
    let mut obj = {
        let mut file = object_base.open(&config.object)?;
        let data = file.map()?;
        if let Some(hash_str) = &config.hash {
            verify_hash(data, hash_str)?;
        }
        process_dol(data, config.name())?
    };
    if config.clean_extab.unwrap_or(false) {
        log::debug!("Cleaning extab for {}", config.name());
        clean_extab(&mut obj, std::iter::empty())?;
    }
    Ok((obj, object_path))
}

fn load_analyze_dol(config: &ProjectConfig, object_base: &ObjectBase) -> Result<AnalyzeResult> {
    let (mut obj, object_path) = load_dol_module(&config.base, object_base)?;
    let mut dep = vec![object_path];

    if let Some(comment_version) = config.mw_comment_version {
        obj.mw_comment = Some(MWComment::new(comment_version)?);
    }

    if let Some(map_path) = &config.base.map {
        let map_path = map_path.with_encoding();
        apply_map_file(&map_path, &mut obj, config.common_start, config.mw_comment_version)?;
        dep.push(map_path);
    }

    let splits_cache = if let Some(splits_path) = &config.base.splits {
        let splits_path = splits_path.with_encoding();
        let cache = apply_splits_file(&splits_path, &mut obj)?;
        dep.push(splits_path);
        cache
    } else {
        None
    };

    let symbols_cache = if let Some(symbols_path) = &config.base.symbols {
        let symbols_path = symbols_path.with_encoding();
        let cache = apply_symbols_file(&symbols_path, &mut obj)?;
        dep.push(symbols_path);
        cache
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
        let selfile_path = object_base.join(selfile);
        log::info!("Loading {}", selfile_path);
        let mut file = object_base.open(selfile)?;
        let data = file.map()?;
        if let Some(hash) = &config.selfile_hash {
            verify_hash(data, hash)?;
        }
        apply_selfile(&mut obj, data)?;
        dep.push(selfile_path);
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
    base_dir: &Utf8NativePath,
    out_dir: &Utf8NativePath,
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
            write_symbols_file(&symbols_path.with_encoding(), &module.obj, module.symbols_cache)?;
        }
        if let Some(splits_path) = &module.config.splits {
            write_splits_file(
                &splits_path.with_encoding(),
                &module.obj,
                false,
                module.splits_cache,
            )?;
        }
    }

    debug!("Splitting {} objects", module.obj.link_order.len());
    let module_name = module.config.name().to_string();
    let split_objs = split_obj(&module.obj, Some(module_name.as_str()))?;

    debug!("Writing object files");
    DirBuilder::new()
        .recursive(true)
        .create(out_dir)
        .with_context(|| format!("Failed to create out dir '{out_dir}'"))?;
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
        ldscript: out_dir.join("ldscript.lcf").with_unix_encoding(),
        units: Vec::with_capacity(split_objs.len()),
        entry,
        extract: Vec::with_capacity(module.config.extract.len()),
    };
    let mut object_paths = BTreeMap::new();
    for (unit, split_obj) in module.obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj, config.export_all)?;
        let obj_path = obj_path_for_unit(&unit.name);
        let out_path = obj_dir.join(&obj_path);
        if let Some(existing) = object_paths.insert(obj_path, unit) {
            bail!(
                "Duplicate object path: {} and {} both resolve to {}",
                existing.name,
                unit.name,
                out_path,
            );
        }
        out_config.units.push(OutputUnit {
            object: out_path.with_unix_encoding(),
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
            .by_ref(&module.obj.sections, &extract.symbol)?
            .with_context(|| format!("Failed to locate symbol '{}'", extract.symbol))?;
        let section_index =
            symbol.section.with_context(|| format!("Symbol '{}' has no section", symbol.name))?;
        let section = &module.obj.sections[section_index];
        let data = section.symbol_data(symbol)?;

        if let Some(binary) = &extract.binary {
            let out_path = base_dir.join("bin").join(binary.with_encoding());
            if let Some(parent) = out_path.parent() {
                DirBuilder::new().recursive(true).create(parent)?;
            }
            write_if_changed(&out_path, data)?;
        }

        let header_kind = match extract.header_type.as_deref() {
            Some(value) => match HeaderKind::from_str(value) {
                Ok(kind) => kind,
                Err(()) => bail!("Invalid header type '{}'", value),
            },
            _ => HeaderKind::Symbol,
        };

        if header_kind != HeaderKind::None {
            if let Some(header) = &extract.header {
                let header_string =
                    bin2c(symbol, section, data, header_kind, extract.rename.as_deref());
                let out_path = base_dir.join("include").join(header.with_encoding());
                if let Some(parent) = out_path.parent() {
                    DirBuilder::new().recursive(true).create(parent)?;
                }
                write_if_changed(&out_path, header_string.as_bytes())?;
            }
        }

        // Copy to output config
        out_config.extract.push(OutputExtract {
            symbol: symbol.name.clone(),
            rename: extract.rename.clone(),
            binary: extract.binary.clone(),
            header: extract.header.clone(),
            header_type: header_kind.to_string(),
            custom_type: extract.custom_type.clone(),
            custom_data: extract.custom_data.clone(),
        });
    }

    // Generate ldscript.lcf
    let ldscript_template = if let Some(template_path) = &module.config.ldscript_template {
        let template_path = template_path.with_encoding();
        let template = fs::read_to_string(&template_path)
            .with_context(|| format!("Failed to read linker script template '{template_path}'"))?;
        module.dep.push(template_path);
        Some(template)
    } else {
        None
    };
    let ldscript_string =
        generate_ldscript(&module.obj, ldscript_template.as_deref(), &module.config.force_active)?;
    let ldscript_path = out_config.ldscript.with_encoding();
    write_if_changed(&ldscript_path, ldscript_string.as_bytes())?;

    if config.write_asm {
        debug!("Writing disassembly");
        let asm_dir = out_dir.join("asm");
        for (unit, split_obj) in module.obj.link_order.iter().zip(&split_objs) {
            let out_path = asm_dir.join(asm_path_for_unit(&unit.name));

            let mut w = buf_writer(&out_path)?;
            write_asm(&mut w, split_obj).with_context(|| format!("Failed to write {out_path}"))?;
            w.flush()?;
        }
    }
    Ok(out_config)
}

fn write_if_changed(path: &Utf8NativePath, contents: &[u8]) -> Result<()> {
    if fs::metadata(path).is_ok_and(|m| m.is_file()) {
        let mut old_file = open_file(path, true)?;
        let old_data = old_file.map()?;
        // If the file is the same size, check if the contents are the same
        // Avoid writing if unchanged, since it will update the file's mtime
        if old_data.len() == contents.len() && xxh3_64(old_data) == xxh3_64(contents) {
            return Ok(());
        }
    }
    fs::write(path, contents).with_context(|| format!("Failed to write file '{path}'"))?;
    Ok(())
}

fn load_analyze_rel(
    config: &ProjectConfig,
    object_base: &ObjectBase,
    module_config: &ModuleConfig,
) -> Result<AnalyzeResult> {
    let object_path = object_base.join(&module_config.object);
    debug!("Loading {}", object_path);
    let mut file = object_base.open(&module_config.object)?;
    let data = file.map()?;
    if let Some(hash_str) = &module_config.hash {
        verify_hash(data, hash_str)?;
    }
    let (header, mut module_obj) = process_rel(&mut Cursor::new(data), module_config.name())?;

    if let Some(comment_version) = config.mw_comment_version {
        module_obj.mw_comment = Some(MWComment::new(comment_version)?);
    }

    let mut dep = vec![object_path];
    if let Some(map_path) = &module_config.map {
        let map_path = map_path.with_encoding();
        apply_map_file(&map_path, &mut module_obj, None, None)?;
        dep.push(map_path);
    }

    let splits_cache = if let Some(splits_path) = &module_config.splits {
        let splits_path = splits_path.with_encoding();
        let cache = apply_splits_file(&splits_path, &mut module_obj)?;
        dep.push(splits_path);
        cache
    } else {
        None
    };

    let symbols_cache = if let Some(symbols_path) = &module_config.symbols {
        let symbols_path = symbols_path.with_encoding();
        let cache = apply_symbols_file(&symbols_path, &mut module_obj)?;
        dep.push(symbols_path);
        cache
    } else {
        None
    };

    // Apply block relocations from config
    apply_block_relocations(&mut module_obj, &module_config.block_relocations)?;

    if !config.symbols_known {
        debug!("Analyzing module {}", module_obj.module_id);
        if !config.quick_analysis {
            let mut state = AnalyzerState::default();
            FindSaveRestSleds::execute(&mut state, &module_obj)?;
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
        rayon::ThreadPoolBuilder::new().num_threads(jobs).build_global()?;
    }

    let command_start = Instant::now();
    info!("Loading {}", args.config);
    let mut config: ProjectConfig = {
        let mut config_file = open_file(&args.config, true)?;
        serde_yaml::from_reader(config_file.as_mut())?
    };

    let mut object_base = find_object_base(&config)?;
    if config.extract_objects && matches!(object_base, ObjectBase::Vfs(..)) {
        // Extract files from the VFS into the object base directory
        let target_dir = extract_objects(&config, &object_base)?;
        object_base = ObjectBase::Directory(target_dir);
    }

    for module_config in config.modules.iter_mut() {
        let mut file = object_base.open(&module_config.object)?;
        let mut data = file.map()?;
        if let Some(hash_str) = &module_config.hash {
            verify_hash(data, hash_str)?;
        } else {
            module_config.hash = Some(file_sha1_string(&mut data)?);
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
                Some(load_analyze_dol(&config, &object_base).with_context(|| {
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
                        load_analyze_rel(&config, &object_base, module_config).with_context(|| {
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
            dep: Default::default(),
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
                dep: Default::default(),
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
        update_symbols(&mut dol.obj, &modules.values().collect::<Vec<_>>(), !config.symbols_known)
            .with_context(|| format!("Updating symbols for module {}", dol.config.name()))?;
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links(&module, &modules)?;
            update_symbols(&mut module.obj, &links, !config.symbols_known)
                .with_context(|| format!("Updating symbols for module {}", module.config.name()))?;
            modules.insert(module_name.clone(), module);
        }

        // Create relocations to symbols in other modules
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links_map(&module, &modules)?;
            create_relocations(&mut module.obj, &links, &dol.obj).with_context(|| {
                format!("Creating relocations for module {}", module.config.name())
            })?;
            modules.insert(module_name.clone(), module);
        }

        // Replace external relocations with internal ones, creating extern symbols
        for module_name in &module_names {
            let mut module = modules.remove(module_name).unwrap();
            let links = get_links_map(&module, &modules)?;
            resolve_external_relocations(&mut module.obj, &links, Some(&dol.obj)).with_context(
                || format!("Resolving external relocations for module {}", module.config.name()),
            )?;
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
                        let out_dir = args.out_dir.join(module.config.name());
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
    dep.extend(dol.dep);
    for module in modules.into_values() {
        dep.extend(module.dep);
    }
    {
        let dep_path = args.out_dir.join("dep");
        let mut dep_file = buf_writer(&dep_path)?;
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
fn validate(obj: &ObjInfo, elf_file: &Utf8NativePath, state: &AnalyzerState) -> Result<()> {
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

/// Check if two symbols' names match, allowing for differences in compiler-generated names,
/// like @1234 and @5678, or init$1234 and init$5678.
fn symbol_name_fuzzy_eq(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Match e.g. @1234 and @5678
    if a.starts_with('@') && b.starts_with('@') {
        return true;
    }
    // Match e.g. init$1234 and init$5678
    if let (Some(a_dollar), Some(b_dollar)) = (a.rfind('$'), b.rfind('$')) {
        if a[..a_dollar] == b[..b_dollar] {
            if let (Ok(_), Ok(_)) =
                (a[a_dollar + 1..].parse::<u32>(), b[b_dollar + 1..].parse::<u32>())
            {
                return true;
            }
        }
    }
    // Match e.g. symbol and symbol_80123456 (globalized symbol)
    if let Some(a_under) = a.rfind('_') {
        if &a[..a_under] == b && is_hex(&a[a_under + 1..]) {
            return true;
        }
    }
    if let Some(b_under) = b.rfind('_') {
        if a == &b[..b_under] && is_hex(&b[b_under + 1..]) {
            return true;
        }
    }
    false
}

fn is_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f' | 'A'..='F'))
}

fn diff(args: DiffArgs) -> Result<()> {
    log::info!("Loading {}", args.config);
    let mut config_file = open_file(&args.config, true)?;
    let config: ProjectConfig = serde_yaml::from_reader(config_file.as_mut())?;
    let object_base = find_object_base(&config)?;

    let (mut obj, _object_path) = load_dol_module(&config.base, &object_base)?;

    if let Some(symbols_path) = &config.base.symbols {
        apply_symbols_file(&symbols_path.with_encoding(), &mut obj)?;
    }

    log::info!("Loading {}", args.elf_file);
    let linked_obj = process_elf(&args.elf_file)?;

    let common_bss = obj.sections.common_bss_start();
    for (_, orig_sym) in obj.symbols.iter().filter(|(_, s)| {
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
            if symbol_name_fuzzy_eq(&linked_sym.name, &orig_sym.name) {
                if linked_sym.size != orig_sym.size &&
                    // TODO validate common symbol sizes
                    // (need to account for inflation bug)
                    matches!(common_bss, Some(addr) if
                        orig_section_index == addr.section && orig_sym.address as u32 >= addr.address)
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
            } else if linked_sym.kind == orig_sym.kind {
                // Fuzzy match
                let orig_data = orig_section.data_range(
                    orig_sym.address as u32,
                    orig_sym.address as u32 + orig_sym.size as u32,
                )?;
                let linked_data = linked_section.data_range(
                    linked_sym.address as u32,
                    linked_sym.address as u32 + linked_sym.size as u32,
                )?;
                let len = orig_data.len().min(linked_data.len());
                if orig_data[..len] == linked_data[..len]
                    // Ignore padding differences
                    && orig_data[len..].iter().all(|&b| b == 0)
                    && linked_data[len..].iter().all(|&b| b == 0)
                {
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
    for (_, orig_sym) in obj.symbols.iter().filter(|(_, s)| {
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
        let len = orig_data.len().min(linked_data.len());
        if orig_data[..len] != linked_data[..len]
            || orig_data[len..].iter().any(|&b| b != 0)
            || linked_data[len..].iter().any(|&b| b != 0)
        {
            log::error!(
                "Data mismatch for {} (type {:?}, size {:#X}) at {:#010X}",
                orig_sym.name,
                orig_sym.kind,
                orig_sym.size,
                orig_sym.address
            );

            // Disassemble and print the diff using objdiff-core if it's a function
            let mut handled = false;
            if orig_sym.kind == ObjSymbolKind::Function
                && orig_section.kind == ObjSectionKind::Code
                && linked_sym.kind == ObjSymbolKind::Function
                && linked_section.kind == ObjSectionKind::Code
            {
                let config = objdiff_core::diff::DiffObjConfig::default();
                let orig_code = process_code(&obj, orig_sym, orig_section, &config)?;
                let linked_code = process_code(&linked_obj, linked_sym, linked_section, &config)?;
                let (left_diff, right_diff) = objdiff_core::diff::code::diff_code(
                    &orig_code,
                    &linked_code,
                    objdiff_core::obj::SymbolRef::default(),
                    objdiff_core::obj::SymbolRef::default(),
                    &config,
                )?;
                let ranges = calc_diff_ranges(&left_diff.instructions, &right_diff.instructions, 3);
                // objdiff may miss relocation differences, so fall back to printing the data diff
                // if we don't have any instruction ranges to print
                if !ranges.is_empty() {
                    print_diff(&left_diff, &right_diff, &ranges)?;
                    handled = true;
                }
            }
            if !handled {
                log::error!("Original: {}", hex::encode_upper(orig_data));
                log::error!("Linked:   {}", hex::encode_upper(linked_data));
            }

            std::process::exit(1);
        } else if orig_data.len() != linked_data.len() {
            log::error!(
                "Size mismatch for {} (type {:?}) at {:#010X}: Expected {:#X}, found {:#X}",
                orig_sym.name,
                orig_sym.kind,
                orig_sym.address,
                orig_data.len(),
                linked_data.len()
            );
        }
    }

    log::info!("OK");
    Ok(())
}

fn are_local_anonymous_names_similar<'a>(left: &'a ObjSymbol, right: &'a ObjSymbol) -> bool {
    if left.flags.scope() != ObjSymbolScope::Local || right.flags.scope() != ObjSymbolScope::Local {
        return false;
    }

    let is_at_symbol =
        |name: &str| name.starts_with('@') && name[1..].chars().all(|c| c.is_numeric());

    if is_at_symbol(&left.name) && is_at_symbol(&right.name) {
        // consider e.g. @8280 -> @8536 equal
        return true;
    }

    let split_dollar_symbol = |name: &'a str| -> Option<&'a str> {
        name.rsplit_once('$')
            .and_then(|(prefix, suffix)| suffix.chars().all(|c| c.is_numeric()).then_some(prefix))
    };

    // consider e.g. __arraydtor$3926 -> __arraydtor$7669 equal
    match (split_dollar_symbol(&left.name), split_dollar_symbol(&right.name)) {
        (Some(left_prefix), Some(right_prefix)) => left_prefix == right_prefix,
        _ => false,
    }
}

fn apply(args: ApplyArgs) -> Result<()> {
    log::info!("Loading {}", args.config);
    let mut config_file = open_file(&args.config, true)?;
    let config: ProjectConfig = serde_yaml::from_reader(config_file.as_mut())?;
    let object_base = find_object_base(&config)?;

    let (mut obj, _object_path) = load_dol_module(&config.base, &object_base)?;

    let Some(symbols_path) = &config.base.symbols else {
        bail!("No symbols file specified in config");
    };
    let symbols_path = symbols_path.with_encoding();
    let Some(symbols_cache) = apply_symbols_file(&symbols_path, &mut obj)? else {
        bail!("Symbols file '{}' does not exist", symbols_path);
    };

    log::info!("Loading {}", args.elf_file);
    let linked_obj = process_elf(&args.elf_file)?;

    let mut replacements: Vec<(SymbolIndex, Option<ObjSymbol>)> = vec![];
    for (orig_idx, orig_sym) in obj.symbols.iter() {
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
                || (!is_globalized
                    && (linked_sym.name != orig_sym.name
                        && (args.full || !are_local_anonymous_names_similar(linked_sym, orig_sym))))
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
    for (_, linked_sym) in linked_obj.symbols.iter() {
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

    let symbols_path = config.base.symbols.as_ref().unwrap();
    write_symbols_file(&symbols_path.with_encoding(), &obj, Some(symbols_cache))?;

    Ok(())
}

fn config(args: ConfigArgs) -> Result<()> {
    let mut config = ProjectConfig::default();
    let mut modules = Vec::<(u32, ModuleConfig)>::new();
    for result in FileIterator::new(&args.objects)? {
        let (path, mut entry) = result?;
        log::info!("Loading {}", path);
        let Some(ext) = path.extension() else {
            bail!("No file extension for {}", path);
        };
        match ext.to_ascii_lowercase().as_str() {
            "dol" => {
                config.base.object = path.with_unix_encoding();
                config.base.hash = Some(file_sha1_string(&mut entry)?);
            }
            "rel" => {
                let header = process_rel_header(&mut entry)?;
                entry.rewind()?;
                modules.push((header.module_id, ModuleConfig {
                    object: path.with_unix_encoding(),
                    hash: Some(file_sha1_string(&mut entry)?),
                    ..Default::default()
                }));
            }
            "sel" => {
                config.selfile = Some(path.with_unix_encoding());
                config.selfile_hash = Some(file_sha1_string(&mut entry)?);
            }
            "rso" => {
                config.modules.push(ModuleConfig {
                    object: path.with_unix_encoding(),
                    hash: Some(file_sha1_string(&mut entry)?),
                    ..Default::default()
                });
            }
            _ => bail!("Unknown file extension: '{}'", ext),
        }
    }
    modules.sort_by(|(a_id, a_config), (b_id, b_config)| {
        // Sort by module ID, then by name
        a_id.cmp(b_id).then(a_config.name().cmp(b_config.name()))
    });
    config.modules.extend(modules.into_iter().map(|(_, m)| m));

    let mut out = buf_writer(&args.out_file)?;
    serde_yaml::to_writer(&mut out, &config)?;
    out.flush()?;
    Ok(())
}

/// Applies the blocked relocation ranges from module config `blocked_relocations`
pub(crate) fn apply_block_relocations(
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
pub(crate) fn apply_add_relocations(
    obj: &mut ObjInfo,
    relocations: &[AddRelocationConfig],
) -> Result<()> {
    for reloc in relocations {
        let SectionAddress { section, address } = reloc.source.resolve(obj)?;
        let (target_symbol, _) = match obj.symbols.by_ref(&obj.sections, &reloc.target)? {
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

pub enum ObjectBase {
    None,
    Directory(Utf8NativePathBuf),
    Vfs(Utf8NativePathBuf, Box<dyn Vfs + Send + Sync>),
}

impl ObjectBase {
    pub fn join(&self, path: &Utf8UnixPath) -> Utf8NativePathBuf {
        match self {
            ObjectBase::None => path.with_encoding(),
            ObjectBase::Directory(base) => {
                // If the extracted file exists, use it directly
                let extracted = extracted_path(base, path);
                if fs::exists(&extracted).unwrap_or(false) {
                    return extracted;
                }
                base.join(path.with_encoding())
            }
            ObjectBase::Vfs(base, _) => Utf8NativePathBuf::from(format!("{base}:{path}")),
        }
    }

    pub fn open(&self, path: &Utf8UnixPath) -> Result<Box<dyn VfsFile>> {
        match self {
            ObjectBase::None => open_file(&path.with_encoding(), true),
            ObjectBase::Directory(base) => {
                // If the extracted file exists, use it directly
                let extracted = extracted_path(base, path);
                if fs::exists(&extracted).unwrap_or(false) {
                    return open_file(&extracted, true);
                }
                open_file(&base.join(path.with_encoding()), true)
            }
            ObjectBase::Vfs(vfs_path, vfs) => {
                open_file_with_fs(vfs.clone(), &path.with_encoding(), true)
                    .with_context(|| format!("Using disc image {vfs_path}"))
            }
        }
    }

    pub fn base_path(&self) -> &Utf8NativePath {
        match self {
            ObjectBase::None => Utf8NativePath::new(""),
            ObjectBase::Directory(base) => base,
            ObjectBase::Vfs(base, _) => base,
        }
    }
}

pub fn find_object_base(config: &ProjectConfig) -> Result<ObjectBase> {
    if let Some(base) = &config.object_base {
        let base = base.with_encoding();
        // Search for disc images in the object base directory
        for result in fs::read_dir(&base).with_context(|| format!("Reading directory {base}"))? {
            let entry = result.with_context(|| format!("Reading entry in directory {base}"))?;
            let Ok(path) = check_path_buf(entry.path()) else {
                log::warn!("Path is not valid UTF-8: {:?}", entry.path());
                continue;
            };
            let file_type =
                entry.file_type().with_context(|| format!("Getting file type for {path}"))?;
            let is_file = if file_type.is_symlink() {
                // Also traverse symlinks to files
                fs::metadata(&path)
                    .with_context(|| format!("Getting metadata for {path}"))?
                    .is_file()
            } else {
                file_type.is_file()
            };
            if is_file {
                let mut file = open_file(&path, false)?;
                let format = detect(file.as_mut())
                    .with_context(|| format!("Detecting file type for {path}"))?;
                match format {
                    FileFormat::Archive(ArchiveKind::Disc(format)) => {
                        let fs = open_fs(file, ArchiveKind::Disc(format))?;
                        return Ok(ObjectBase::Vfs(path, fs));
                    }
                    FileFormat::Archive(ArchiveKind::Wad) => {
                        let fs = open_fs(file, ArchiveKind::Wad)?;
                        return Ok(ObjectBase::Vfs(path, fs));
                    }
                    _ => {}
                }
            }
        }
        return Ok(ObjectBase::Directory(base));
    }
    Ok(ObjectBase::None)
}

/// Extracts object files from the disc image into the object base directory.
fn extract_objects(config: &ProjectConfig, object_base: &ObjectBase) -> Result<Utf8NativePathBuf> {
    let target_dir: Utf8NativePathBuf = match config.object_base.as_ref() {
        Some(path) => path.with_encoding(),
        None => bail!("No object base specified"),
    };
    let mut object_paths = Vec::<(&Utf8UnixPath, Option<&str>, Utf8NativePathBuf)>::new();
    {
        let target_path = extracted_path(&target_dir, &config.base.object);
        if !fs::exists(&target_path)
            .with_context(|| format!("Failed to check path '{target_path}'"))?
        {
            object_paths.push((&config.base.object, config.base.hash.as_deref(), target_path));
        }
    }
    if let Some(selfile) = &config.selfile {
        let target_path = extracted_path(&target_dir, selfile);
        if !fs::exists(&target_path)
            .with_context(|| format!("Failed to check path '{target_path}'"))?
        {
            object_paths.push((selfile, config.selfile_hash.as_deref(), target_path));
        }
    }
    for module_config in &config.modules {
        let target_path = extracted_path(&target_dir, &module_config.object);
        if !fs::exists(&target_path)
            .with_context(|| format!("Failed to check path '{target_path}'"))?
        {
            object_paths.push((&module_config.object, module_config.hash.as_deref(), target_path));
        }
    }
    if object_paths.is_empty() {
        return Ok(target_dir);
    }
    log::info!(
        "Extracting {} file{} from {}",
        object_paths.len(),
        if object_paths.len() == 1 { "" } else { "s" },
        object_base.base_path()
    );
    let start = Instant::now();
    for (source_path, hash, target_path) in object_paths {
        let mut file = object_base.open(source_path)?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory '{parent}'"))?;
        }
        let mut out = fs::File::create(&target_path)
            .with_context(|| format!("Failed to create file '{target_path}'"))?;
        let hash_bytes = buf_copy_with_hash(&mut file, &mut out)
            .with_context(|| format!("Failed to extract file '{target_path}'"))?;
        if let Some(hash) = hash {
            check_hash_str(hash_bytes, hash).with_context(|| {
                format!("Source file failed verification: '{}'", object_base.join(source_path))
            })?;
        }
    }
    let duration = start.elapsed();
    log::info!("Extraction completed in {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    Ok(target_dir)
}

/// Converts VFS paths like `path/to/container.arc:file` to `path/to/container/file`.
fn extracted_path(target_dir: &Utf8NativePath, path: &Utf8UnixPath) -> Utf8NativePathBuf {
    let mut target_path = target_dir.to_owned();
    let mut split = path.as_str().split(':').peekable();
    while let Some(path) = split.next() {
        let path = Utf8UnixPath::new(path);
        if split.peek().is_some() {
            if let Some(parent) = path.parent() {
                target_path.push(parent.with_encoding());
            }
            target_path.push(path.file_stem().unwrap());
        } else {
            target_path.push(path.with_encoding());
        }
    }
    target_path
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_symbol_name_fuzzy_eq() {
        assert!(symbol_name_fuzzy_eq("symbol", "symbol"));
        assert!(symbol_name_fuzzy_eq("@1234", "@5678"));
        assert!(symbol_name_fuzzy_eq("symbol$1234", "symbol$5678"));
        assert!(symbol_name_fuzzy_eq("symbol", "symbol_80123456"));
        assert!(symbol_name_fuzzy_eq("symbol_80123456", "symbol"));
        assert!(!symbol_name_fuzzy_eq("symbol", "symbol2"));
        assert!(!symbol_name_fuzzy_eq("symbol@1234", "symbol@5678"));
        assert!(!symbol_name_fuzzy_eq("symbol", "symbol_80123456_"));
        assert!(!symbol_name_fuzzy_eq("symbol_80123456_", "symbol"));
    }
}
