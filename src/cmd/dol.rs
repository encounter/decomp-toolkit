use anyhow::{bail, Result};
use cwdemangle::demangle;
use serde::{Deserialize, Serialize};
use typed_path::Utf8UnixPathBuf;

use crate::{
    analysis::cfa::SectionAddress,
    obj::{ObjInfo, ObjReloc, ObjRelocKind, ObjSymbol},
    util::config::{signed_hex_serde, SectionAddressRef},
};

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
