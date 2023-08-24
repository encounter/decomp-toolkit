use std::{
    collections::{btree_map, BTreeMap},
    error::Error,
    fmt,
    ops::RangeBounds,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::obj::SymbolIndex;

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
    // pub address: u64,
    pub target_symbol: SymbolIndex,
    pub addend: i64,
    /// If present, relocation against external module
    pub module: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct ObjRelocations {
    relocations: BTreeMap<u32, ObjReloc>,
}

#[derive(Debug)]
pub struct ExistingRelocationError {
    pub address: u32,
    pub value: ObjReloc,
}

impl fmt::Display for ExistingRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "relocation already exists at address {:#010X}", self.address)
    }
}

impl Error for ExistingRelocationError {}

impl ObjRelocations {
    pub fn new(relocations: Vec<(u32, ObjReloc)>) -> Result<Self, ExistingRelocationError> {
        let mut map = BTreeMap::new();
        for (address, reloc) in relocations {
            let address = address & !3;
            match map.entry(address) {
                btree_map::Entry::Vacant(e) => e.insert(reloc),
                btree_map::Entry::Occupied(e) => {
                    return Err(ExistingRelocationError { address, value: e.get().clone() })
                }
            };
        }
        Ok(Self { relocations: map })
    }

    pub fn len(&self) -> usize { self.relocations.len() }

    pub fn insert(&mut self, address: u32, reloc: ObjReloc) -> Result<(), ExistingRelocationError> {
        let address = address & !3;
        match self.relocations.entry(address) {
            btree_map::Entry::Vacant(e) => e.insert(reloc),
            btree_map::Entry::Occupied(e) => {
                return Err(ExistingRelocationError { address, value: e.get().clone() })
            }
        };
        Ok(())
    }

    pub fn replace(&mut self, address: u32, reloc: ObjReloc) {
        self.relocations.insert(address, reloc);
    }

    pub fn at(&self, address: u32) -> Option<&ObjReloc> { self.relocations.get(&address) }

    pub fn at_mut(&mut self, address: u32) -> Option<&mut ObjReloc> {
        self.relocations.get_mut(&address)
    }

    pub fn clone_map(&self) -> BTreeMap<u32, ObjReloc> { self.relocations.clone() }

    pub fn is_empty(&self) -> bool { self.relocations.is_empty() }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u32, &ObjReloc)> {
        self.relocations.iter().map(|(&addr, reloc)| (addr, reloc))
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (u32, &mut ObjReloc)> {
        self.relocations.iter_mut().map(|(&addr, reloc)| (addr, reloc))
    }

    pub fn range<R>(&self, range: R) -> impl DoubleEndedIterator<Item = (u32, &ObjReloc)>
    where R: RangeBounds<u32> {
        self.relocations.range(range).map(|(&addr, reloc)| (addr, reloc))
    }

    pub fn contains(&self, address: u32) -> bool { self.relocations.contains_key(&address) }
}
