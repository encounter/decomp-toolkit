use std::{
    collections::{btree_map, BTreeMap},
    hash::{Hash, Hasher},
};

use anyhow::{Error, Result};
use flagset::{flags, FlagSet};

flags! {
    pub enum ObjSymbolFlags: u8 {
        Global,
        Local,
        Weak,
        Common,
        Hidden,
    }
}
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct ObjSymbolFlagSet(pub(crate) FlagSet<ObjSymbolFlags>);
#[allow(clippy::derive_hash_xor_eq)]
impl Hash for ObjSymbolFlagSet {
    fn hash<H: Hasher>(&self, state: &mut H) { self.0.bits().hash(state) }
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjSectionKind {
    Code,
    Data,
    ReadOnlyData,
    Bss,
}
#[derive(Debug, Clone)]
pub struct ObjSection {
    pub name: String,
    pub kind: ObjSectionKind,
    pub address: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub align: u64,
    pub index: usize,
    pub relocations: Vec<ObjReloc>,
    pub original_address: u64,
    pub file_offset: u64,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum ObjSymbolKind {
    #[default]
    Unknown,
    Function,
    Object,
    Section,
}
#[derive(Debug, Clone, Default)]
pub struct ObjSymbol {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub section: Option<usize>,
    pub size: u64,
    pub size_known: bool,
    pub flags: ObjSymbolFlagSet,
    pub kind: ObjSymbolKind,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjKind {
    /// Fully linked file
    Executable,
    /// Relocatable file
    Relocatable,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjArchitecture {
    PowerPc,
}
#[derive(Debug, Clone)]
pub struct ObjInfo {
    pub kind: ObjKind,
    pub architecture: ObjArchitecture,
    pub name: String,
    pub symbols: Vec<ObjSymbol>,
    pub sections: Vec<ObjSection>,
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
    pub target_symbol: usize,
    pub addend: i64,
}

impl ObjInfo {
    pub fn symbols_for_section(
        &self,
        section_idx: usize,
    ) -> impl Iterator<Item = (usize, &ObjSymbol)> {
        self.symbols
            .iter()
            .enumerate()
            .filter(move |&(_, symbol)| symbol.section == Some(section_idx))
    }

    pub fn build_symbol_map(&self, section_idx: usize) -> Result<BTreeMap<u32, Vec<usize>>> {
        let mut symbols = BTreeMap::<u32, Vec<usize>>::new();
        for (symbol_idx, symbol) in self.symbols_for_section(section_idx) {
            let address = symbol.address as u32;
            nested_push(&mut symbols, address, symbol_idx);
        }
        Ok(symbols)
    }
}

impl ObjSection {
    pub fn build_relocation_map(&self) -> Result<BTreeMap<u32, ObjReloc>> {
        let mut relocations = BTreeMap::<u32, ObjReloc>::new();
        for reloc in &self.relocations {
            let address = reloc.address as u32;
            match relocations.entry(address) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(reloc.clone());
                }
                btree_map::Entry::Occupied(_) => {
                    return Err(Error::msg(format!("Duplicate relocation @ {address:#010X}")));
                }
            }
        }
        Ok(relocations)
    }
}

#[inline]
pub fn nested_push<T1, T2>(map: &mut BTreeMap<T1, Vec<T2>>, v1: T1, v2: T2)
where T1: Ord {
    match map.entry(v1) {
        btree_map::Entry::Occupied(mut e) => {
            e.get_mut().push(v2);
        }
        btree_map::Entry::Vacant(e) => {
            e.insert(vec![v2]);
        }
    }
}
