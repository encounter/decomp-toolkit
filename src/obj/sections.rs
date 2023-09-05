use std::{
    cmp::min,
    collections::Bound,
    ops::{Index, IndexMut, Range, RangeBounds},
};

use anyhow::{anyhow, bail, ensure, Result};
use itertools::Itertools;

use crate::obj::{ObjKind, ObjRelocations, ObjSplit, ObjSplits, ObjSymbol};

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
    /// REL files reference the original ELF section indices
    pub elf_index: usize,
    pub relocations: ObjRelocations,
    pub original_address: u64,
    pub file_offset: u64,
    pub section_known: bool,
    pub splits: ObjSplits,
}

#[derive(Debug, Clone)]
pub struct ObjSections {
    obj_kind: ObjKind,
    sections: Vec<ObjSection>,
}

impl ObjSections {
    pub fn new(obj_kind: ObjKind, sections: Vec<ObjSection>) -> Self { Self { obj_kind, sections } }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (usize, &ObjSection)> {
        self.sections.iter().enumerate()
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (usize, &mut ObjSection)> {
        self.sections.iter_mut().enumerate()
    }

    pub fn count(&self) -> usize { self.sections.len() }

    pub fn next_section_index(&self) -> usize { self.sections.len() }

    pub fn get(&self, index: usize) -> Option<&ObjSection> { self.sections.get(index) }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut ObjSection> {
        self.sections.get_mut(index)
    }

    pub fn get_elf_index(&self, elf_index: usize) -> Option<(usize, &ObjSection)> {
        self.iter().find(|&(_, s)| s.elf_index == elf_index)
    }

    pub fn get_elf_index_mut(&mut self, elf_index: usize) -> Option<(usize, &mut ObjSection)> {
        self.iter_mut().find(|(_, s)| s.elf_index == elf_index)
    }

    pub fn at_address(&self, addr: u32) -> Result<(usize, &ObjSection)> {
        ensure!(
            self.obj_kind == ObjKind::Executable,
            "Use of ObjSections::at_address in relocatable object"
        );
        self.iter()
            .find(|&(_, s)| s.contains(addr))
            .ok_or_else(|| anyhow!("Failed to locate section @ {:#010X}", addr))
    }

    pub fn at_address_mut(&mut self, addr: u32) -> Result<(usize, &mut ObjSection)> {
        ensure!(
            self.obj_kind == ObjKind::Executable,
            "Use of ObjSections::at_address_mut in relocatable object"
        );
        self.iter_mut()
            .find(|(_, s)| s.contains(addr))
            .ok_or_else(|| anyhow!("Failed to locate section @ {:#010X}", addr))
    }

    pub fn with_range(&self, range: Range<u32>) -> Result<(usize, &ObjSection)> {
        ensure!(
            self.obj_kind == ObjKind::Executable,
            "Use of ObjSections::with_range in relocatable object"
        );
        self.iter().find(|&(_, s)| s.contains_range(range.clone())).ok_or_else(|| {
            anyhow!("Failed to locate section @ {:#010X}-{:#010X}", range.start, range.end)
        })
    }

    pub fn by_kind(
        &self,
        kind: ObjSectionKind,
    ) -> impl DoubleEndedIterator<Item = (usize, &ObjSection)> {
        self.iter().filter(move |(_, s)| s.kind == kind)
    }

    pub fn by_name(&self, name: &str) -> Result<Option<(usize, &ObjSection)>> {
        self.iter()
            .filter(move |(_, s)| s.name == name)
            .at_most_one()
            .map_err(|_| anyhow!("Multiple sections with name {}", name))
    }

    pub fn push(&mut self, section: ObjSection) -> usize {
        let index = self.sections.len();
        self.sections.push(section);
        index
    }

    pub fn all_splits(
        &self,
    ) -> impl DoubleEndedIterator<Item = (usize, &ObjSection, u32, &ObjSplit)> {
        self.iter()
            .flat_map(|(idx, s)| s.splits.iter().map(move |(addr, split)| (idx, s, addr, split)))
    }
}

impl Index<usize> for ObjSections {
    type Output = ObjSection;

    fn index(&self, index: usize) -> &Self::Output { &self.sections[index] }
}

impl IndexMut<usize> for ObjSections {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output { &mut self.sections[index] }
}

impl ObjSection {
    pub fn data_range(&self, start: u32, end: u32) -> Result<&[u8]> {
        if end == 0 {
            ensure!(
                self.contains(start),
                "Address {:#010X} outside of section {}: {:#010X}-{:#010X}",
                start,
                self.name,
                self.address,
                self.address + self.size
            );
        } else {
            ensure!(
                self.contains_range(start..end),
                "Range {:#010X}-{:#010X} outside of section {}: {:#010X}-{:#010X}",
                start,
                end,
                self.name,
                self.address,
                self.address + self.size
            );
        }
        if self.kind == ObjSectionKind::Bss {
            return Ok(&[]);
        }
        let start = (start as u64 - self.address) as usize;
        Ok(if end == 0 {
            &self.data[start..]
        } else {
            &self.data[start..min(self.data.len(), (end as u64 - self.address) as usize)]
        })
    }

    #[inline]
    pub fn symbol_data(&self, symbol: &ObjSymbol) -> Result<&[u8]> {
        if symbol.size == 0 {
            return Ok(&[]);
        }
        self.data_range(symbol.address as u32, symbol.address as u32 + symbol.size as u32)
    }

    #[inline]
    pub fn contains(&self, addr: u32) -> bool {
        (self.address..self.address + self.size).contains(&(addr as u64))
    }

    #[inline]
    pub fn contains_range<R>(&self, range: R) -> bool
    where R: RangeBounds<u32> {
        let start = self.address as u32;
        let end = self.address as u32 + self.size as u32;
        let start_in_range = match range.start_bound() {
            Bound::Included(&n) => n >= start && n < end,
            Bound::Excluded(&n) => n > start && n < end,
            Bound::Unbounded => true,
        };
        let end_in_range = match range.end_bound() {
            Bound::Included(&n) => n > start && n < end,
            Bound::Excluded(&n) => n > start && n <= end,
            Bound::Unbounded => true,
        };
        start_in_range && end_in_range
    }

    pub fn rename(&mut self, name: String) -> Result<()> {
        self.kind = section_kind_for_section(&name)?;
        self.name = name;
        self.section_known = true;
        Ok(())
    }
}

fn section_kind_for_section(section_name: &str) -> Result<ObjSectionKind> {
    Ok(match section_name {
        ".init" | ".text" | ".dbgtext" | ".vmtext" => ObjSectionKind::Code,
        ".ctors" | ".dtors" | ".rodata" | ".sdata2" | "extab" | "extabindex" => {
            ObjSectionKind::ReadOnlyData
        }
        ".bss" | ".sbss" | ".sbss2" => ObjSectionKind::Bss,
        ".data" | ".sdata" => ObjSectionKind::Data,
        name => bail!("Unknown section {name}"),
    })
}
