use std::{collections::BTreeMap, path::PathBuf};

use flagset::{flags, FlagSet};

flags! {
    pub enum ObjSymbolFlags: u8 {
        Global,
        Local,
        Weak,
        Common,
    }
}
#[derive(Debug, Copy, Clone, Default)]
pub struct ObjSymbolFlagSet(pub(crate) FlagSet<ObjSymbolFlags>);
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ObjSectionKind {
    Code,
    Data,
    Bss,
}
#[derive(Debug, Clone)]
pub struct ObjSection {
    pub name: String,
    pub kind: ObjSectionKind,
    pub address: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub index: usize,
    pub symbols: Vec<ObjSymbol>,
    pub relocations: Vec<ObjReloc>,
    pub file_offset: u64,
}
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ObjSymbolKind {
    Unknown,
    Function,
    Object,
}
#[derive(Debug, Clone)]
pub struct ObjSymbol {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub section_address: u64,
    pub size: u64,
    pub size_known: bool,
    pub flags: ObjSymbolFlagSet,
    pub addend: i64,
    pub kind: ObjSymbolKind,
}
#[derive(Debug, Copy, Clone)]
pub enum ObjArchitecture {
    PowerPc,
}
#[derive(Debug, Clone)]
pub struct ObjInfo {
    pub architecture: ObjArchitecture,
    pub path: PathBuf,
    pub sections: Vec<ObjSection>,
    pub common: Vec<ObjSymbol>,
    pub entry: u32,

    // Linker generated
    pub stack_address: Option<u32>,
    pub stack_end: Option<u32>,
    pub db_stack_addr: Option<u32>,
    pub arena_lo: Option<u32>,
    pub arena_hi: Option<u32>,

    // Extracted
    pub splits: BTreeMap<u32, String>,
    pub link_order: Vec<String>,
}
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ObjRelocKind {
    Absolute,
    PpcAddr16Hi,
    PpcAddr16Ha,
    PpcAddr16Lo,
    PpcRel24,
    PpcRel14,
    PpcEmbSda21,
}
#[derive(Debug, Clone)]
pub struct ObjReloc {
    pub kind: ObjRelocKind,
    pub address: u64,
    pub target: ObjSymbol,
    pub target_section: Option<String>,
}
