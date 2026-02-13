use std::{
    collections::{btree_map, BTreeMap},
    error::Error,
    fmt,
    ops::RangeBounds,
};

use anyhow::Result;
use object::{elf, pe};
use serde::{Deserialize, Serialize};

use crate::obj::SymbolIndex;

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

impl Serialize for ObjRelocKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_str(match self {
            ObjRelocKind::Absolute => "abs",
            ObjRelocKind::PpcAddr16Hi => "hi",
            ObjRelocKind::PpcAddr16Ha => "ha",
            ObjRelocKind::PpcAddr16Lo => "l",
            ObjRelocKind::PpcRel24 => "rel24",
            ObjRelocKind::PpcRel14 => "rel14",
            ObjRelocKind::PpcEmbSda21 => "sda21",
        })
    }
}

impl<'de> Deserialize<'de> for ObjRelocKind {
    fn deserialize<D>(deserializer: D) -> Result<ObjRelocKind, D::Error>
    where D: serde::Deserializer<'de> {
        match String::deserialize(deserializer)?.as_str() {
            "Absolute" | "abs" => Ok(ObjRelocKind::Absolute),
            "PpcAddr16Hi" | "hi" => Ok(ObjRelocKind::PpcAddr16Hi),
            "PpcAddr16Ha" | "ha" => Ok(ObjRelocKind::PpcAddr16Ha),
            "PpcAddr16Lo" | "l" => Ok(ObjRelocKind::PpcAddr16Lo),
            "PpcRel24" | "rel24" => Ok(ObjRelocKind::PpcRel24),
            "PpcRel14" | "rel14" => Ok(ObjRelocKind::PpcRel14),
            "PpcEmbSda21" | "sda21" => Ok(ObjRelocKind::PpcEmbSda21),
            s => Err(serde::de::Error::unknown_variant(s, &[
                "abs", "hi", "ha", "l", "rel24", "rel14", "sda21",
            ])),
        }
    }
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

impl ObjReloc {
    /// Calculates the ELF r_offset and r_type for a relocation.
    pub fn to_elf(&self, addr: u32) -> (u64, u32) {
        let mut r_offset = addr as u64;
        let r_type = match self.kind {
            ObjRelocKind::Absolute => {
                if r_offset & 3 == 0 {
                    elf::R_PPC_ADDR32
                } else {
                    elf::R_PPC_UADDR32
                }
            }
            ObjRelocKind::PpcAddr16Hi => {
                r_offset = (r_offset & !3) + 2;
                elf::R_PPC_ADDR16_HI
            }
            ObjRelocKind::PpcAddr16Ha => {
                r_offset = (r_offset & !3) + 2;
                elf::R_PPC_ADDR16_HA
            }
            ObjRelocKind::PpcAddr16Lo => {
                r_offset = (r_offset & !3) + 2;
                elf::R_PPC_ADDR16_LO
            }
            ObjRelocKind::PpcRel24 => {
                r_offset &= !3;
                elf::R_PPC_REL24
            }
            ObjRelocKind::PpcRel14 => {
                r_offset &= !3;
                elf::R_PPC_REL14
            }
            ObjRelocKind::PpcEmbSda21 => {
                r_offset &= !3;
                elf::R_PPC_EMB_SDA21
            }
        };
        (r_offset, r_type)
    }

    pub fn to_coff(&self) -> u16 {
        match self.kind {
            ObjRelocKind::Absolute => pe::IMAGE_REL_PPC_ADDR32,
            ObjRelocKind::PpcAddr16Hi => {
                unreachable!(); // pe::IMAGE_REL_PPC_ABSOLUTE
            }
            ObjRelocKind::PpcAddr16Ha => pe::IMAGE_REL_PPC_REFHI,
            ObjRelocKind::PpcAddr16Lo => pe::IMAGE_REL_PPC_REFLO,
            ObjRelocKind::PpcRel24 => pe::IMAGE_REL_PPC_REL24,
            ObjRelocKind::PpcRel14 => pe::IMAGE_REL_PPC_REL14,
            ObjRelocKind::PpcEmbSda21 => {
                unreachable!();
            }
        }
    }
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
            // Note: Do NOT align the address here. Data sections can have relocations
            // at unaligned offsets when splits start at non-4-byte-aligned addresses.
            // The to_elf() method already handles alignment appropriately per relocation type.
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
        // Note: Do NOT align the address here. See comment in new().
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_reloc(target_symbol: SymbolIndex) -> ObjReloc {
        ObjReloc { kind: ObjRelocKind::Absolute, target_symbol, addend: 0, module: None }
    }

    /// Test that relocations at unaligned addresses are preserved correctly.
    ///
    /// This reproduces a bug found in XEX splitting where data sections can start
    /// at non-4-byte-aligned addresses. When a split starts at e.g. 0x82F0ABD3,
    /// a relocation at 0x82F0ABD4 becomes relative offset 1. The bug was that
    /// `ObjRelocations::new()` forced 4-byte alignment via `address & !3`,
    /// corrupting offset 1 to offset 0.
    ///
    /// Real-world example from DC3 decomp:
    /// - CharClip.cpp .data split starts at VA 0x82F0ABD3 (unaligned)
    /// - Symbol `smGenerateTransitionGraphOnSave` at offset 0, size 1 byte
    /// - RTTI TypeDescriptor `??_R0PAV?$Key@M@@` at offset 1, needs vtable relocation
    /// - Relocation for vtable pointer should be at offset 1, not 0
    #[test]
    fn test_unaligned_relocation_addresses_preserved() {
        // Simulate relocations at unaligned offsets (as would occur when a split
        // starts at a non-4-byte-aligned address)
        let relocations = vec![
            (1u32, make_test_reloc(100)), // Offset 1 - like RTTI after 1-byte bool
            (5u32, make_test_reloc(101)), // Offset 5
            (9u32, make_test_reloc(102)), // Offset 9
        ];

        let obj_relocs = ObjRelocations::new(relocations).expect("should not fail");

        // Verify relocations are at their original addresses
        assert!(
            obj_relocs.at(1).is_some(),
            "Relocation at offset 1 should exist (BUG: was moved to offset 0 by `& !3`)"
        );
        assert!(
            obj_relocs.at(5).is_some(),
            "Relocation at offset 5 should exist (BUG: was moved to offset 4 by `& !3`)"
        );
        assert!(
            obj_relocs.at(9).is_some(),
            "Relocation at offset 9 should exist (BUG: was moved to offset 8 by `& !3`)"
        );

        // Verify relocations are NOT at aligned addresses (the bug behavior)
        assert!(
            obj_relocs.at(0).is_none(),
            "Relocation should NOT be at offset 0 (this indicates the alignment bug)"
        );
        assert!(
            obj_relocs.at(4).is_none(),
            "Relocation should NOT be at offset 4 (this indicates the alignment bug)"
        );
        assert!(
            obj_relocs.at(8).is_none(),
            "Relocation should NOT be at offset 8 (this indicates the alignment bug)"
        );
    }

    /// Test that insert() also preserves unaligned addresses.
    #[test]
    fn test_insert_unaligned_addresses_preserved() {
        let mut obj_relocs = ObjRelocations::default();

        obj_relocs.insert(1, make_test_reloc(100)).expect("insert should succeed");
        obj_relocs.insert(5, make_test_reloc(101)).expect("insert should succeed");

        assert!(
            obj_relocs.at(1).is_some(),
            "Inserted relocation at offset 1 should be retrievable at offset 1"
        );
        assert!(
            obj_relocs.at(5).is_some(),
            "Inserted relocation at offset 5 should be retrievable at offset 5"
        );
    }

    /// Test that aligned relocations still work correctly.
    #[test]
    fn test_aligned_relocations_work() {
        let relocations = vec![
            (0u32, make_test_reloc(100)),
            (4u32, make_test_reloc(101)),
            (8u32, make_test_reloc(102)),
        ];

        let obj_relocs = ObjRelocations::new(relocations).expect("should not fail");

        assert!(obj_relocs.at(0).is_some());
        assert!(obj_relocs.at(4).is_some());
        assert!(obj_relocs.at(8).is_some());
    }

    /// Test that to_elf() correctly uses R_PPC_UADDR32 for unaligned Absolute relocations.
    #[test]
    fn test_to_elf_unaligned_absolute_uses_uaddr32() {
        let reloc = make_test_reloc(100);

        // Aligned address should use R_PPC_ADDR32
        let (offset, r_type) = reloc.to_elf(0);
        assert_eq!(offset, 0);
        assert_eq!(r_type, object::elf::R_PPC_ADDR32);

        let (offset, r_type) = reloc.to_elf(4);
        assert_eq!(offset, 4);
        assert_eq!(r_type, object::elf::R_PPC_ADDR32);

        // Unaligned address should use R_PPC_UADDR32
        let (offset, r_type) = reloc.to_elf(1);
        assert_eq!(offset, 1);
        assert_eq!(r_type, object::elf::R_PPC_UADDR32);

        let (offset, r_type) = reloc.to_elf(5);
        assert_eq!(offset, 5);
        assert_eq!(r_type, object::elf::R_PPC_UADDR32);
    }
}
