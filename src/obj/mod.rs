pub mod signatures;
pub mod split;

use std::{
    cmp::min,
    collections::{btree_map, BTreeMap},
    hash::{Hash, Hasher},
};

use anyhow::{anyhow, bail, Result};
use flagset::{flags, FlagSet};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::util::{nested::NestedVec, rel::RelReloc};

flags! {
    #[repr(u8)]
    #[derive(Deserialize_repr, Serialize_repr)]
    pub enum ObjSymbolFlags: u8 {
        Global,
        Local,
        Weak,
        Common,
        Hidden,
    }
}
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjSymbolFlagSet(pub FlagSet<ObjSymbolFlags>);
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
    /// REL files reference the original ELF section indices
    pub elf_index: usize,
    pub relocations: Vec<ObjReloc>,
    pub original_address: u64,
    pub file_offset: u64,
    pub section_known: bool,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
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
    /// Fully linked object
    Executable,
    /// Relocatable object
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
    pub entry: u64,

    // Linker generated
    pub sda2_base: Option<u32>,
    pub sda_base: Option<u32>,
    pub stack_address: Option<u32>,
    pub stack_end: Option<u32>,
    pub db_stack_addr: Option<u32>,
    pub arena_lo: Option<u32>,
    pub arena_hi: Option<u32>,

    // Extracted
    pub splits: BTreeMap<u32, Vec<String>>,
    pub named_sections: BTreeMap<u32, String>,
    pub link_order: Vec<String>,

    // From extab
    pub known_functions: BTreeMap<u32, u32>,

    // REL
    /// Module ID (0 for main)
    pub module_id: u32,
    pub unresolved_relocations: Vec<RelReloc>,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
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
            symbols.nested_push(symbol.address as u32, symbol_idx);
        }
        Ok(symbols)
    }

    pub fn section_at(&self, addr: u32) -> Result<&ObjSection> {
        self.sections
            .iter()
            .find(|&section| {
                (addr as u64) >= section.address && (addr as u64) < section.address + section.size
            })
            .ok_or_else(|| anyhow!("Failed to locate section @ {:#010X}", addr))
    }

    pub fn section_data(&self, start: u32, end: u32) -> Result<(&ObjSection, &[u8])> {
        let section = self.section_at(start)?;
        let data = if end == 0 {
            &section.data[(start as u64 - section.address) as usize..]
        } else {
            &section.data[(start as u64 - section.address) as usize
                ..min(section.data.len(), (end as u64 - section.address) as usize)]
        };
        Ok((section, data))
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
                btree_map::Entry::Occupied(_) => bail!("Duplicate relocation @ {address:#010X}"),
            }
        }
        Ok(relocations)
    }
}
