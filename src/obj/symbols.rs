use std::{
    collections::{BTreeMap, HashMap},
    hash::{Hash, Hasher},
    ops::{Index, RangeBounds},
};

use anyhow::{anyhow, bail, ensure, Result};
use flagset::{flags, FlagSet};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    analysis::cfa::SectionAddress,
    obj::{sections::SectionIndex, ObjKind, ObjRelocKind, ObjSections},
    util::{
        config::{is_auto_jump_table, is_auto_label, is_auto_symbol, parse_u32},
        nested::NestedVec,
        split::is_linker_generated_label,
    },
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum ObjSymbolScope {
    #[default]
    Unknown,
    Global,
    Weak,
    Local,
}

flags! {
    #[repr(u32)]
    #[derive(Deserialize_repr, Serialize_repr)]
    pub enum ObjSymbolFlags: u32 {
        Global,
        Local,
        Weak,
        Common,
        Hidden,
        /// Force symbol to be exported (force active)
        Exported,
        /// Symbol isn't referenced by any relocations
        RelocationIgnore,
        /// Symbol won't be written to symbols file
        NoWrite,
        /// Symbol was stripped from the original object,
        /// but is still useful for common BSS matching.
        Stripped,
        /// Disable automatic export of symbol
        NoExport,
        /// Symbol does not contain any relocations
        NoReloc,
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjSymbolFlagSet(pub FlagSet<ObjSymbolFlags>);

impl ObjSymbolFlagSet {
    #[inline]
    pub fn scope(&self) -> ObjSymbolScope {
        if self.is_local() {
            ObjSymbolScope::Local
        } else if self.is_weak() {
            ObjSymbolScope::Weak
        } else if self.0.contains(ObjSymbolFlags::Global) {
            ObjSymbolScope::Global
        } else {
            ObjSymbolScope::Unknown
        }
    }

    #[inline]
    pub fn is_local(&self) -> bool { self.0.contains(ObjSymbolFlags::Local) }

    #[inline]
    pub fn is_global(&self) -> bool { !self.is_local() }

    #[inline]
    pub fn is_common(&self) -> bool { self.0.contains(ObjSymbolFlags::Common) }

    #[inline]
    pub fn is_weak(&self) -> bool { self.0.contains(ObjSymbolFlags::Weak) }

    #[inline]
    pub fn is_hidden(&self) -> bool { self.0.contains(ObjSymbolFlags::Hidden) }

    #[inline]
    pub fn is_exported(&self) -> bool { self.0.contains(ObjSymbolFlags::Exported) }

    #[inline]
    pub fn is_relocation_ignore(&self) -> bool { self.0.contains(ObjSymbolFlags::RelocationIgnore) }

    #[inline]
    pub fn is_no_write(&self) -> bool { self.0.contains(ObjSymbolFlags::NoWrite) }

    #[inline]
    pub fn is_stripped(&self) -> bool { self.0.contains(ObjSymbolFlags::Stripped) }

    #[inline]
    pub fn is_no_export(&self) -> bool { self.0.contains(ObjSymbolFlags::NoExport) }

    #[inline]
    pub fn is_no_reloc(&self) -> bool { self.0.contains(ObjSymbolFlags::NoReloc) }

    #[inline]
    pub fn set_scope(&mut self, scope: ObjSymbolScope) {
        match scope {
            ObjSymbolScope::Unknown => {
                self.0 &= !(ObjSymbolFlags::Local | ObjSymbolFlags::Global | ObjSymbolFlags::Weak)
            }
            ObjSymbolScope::Global => {
                self.0 = (self.0 & !(ObjSymbolFlags::Local | ObjSymbolFlags::Weak))
                    | ObjSymbolFlags::Global
            }
            ObjSymbolScope::Weak => {
                self.0 = (self.0 & !(ObjSymbolFlags::Local | ObjSymbolFlags::Global))
                    | ObjSymbolFlags::Weak
            }
            ObjSymbolScope::Local => {
                self.0 = (self.0 & !(ObjSymbolFlags::Global | ObjSymbolFlags::Weak))
                    | ObjSymbolFlags::Local
            }
        }
    }

    #[inline]
    pub fn set_force_active(&mut self, value: bool) {
        if value {
            self.0 = (self.0 & !ObjSymbolFlags::NoExport) | ObjSymbolFlags::Exported;
        } else {
            self.0 &= !ObjSymbolFlags::Exported;
        }
    }

    /// Special flags to keep when merging symbols.
    #[inline]
    pub fn keep_flags(&self) -> FlagSet<ObjSymbolFlags> {
        self.0
            & (ObjSymbolFlags::Exported
                | ObjSymbolFlags::NoWrite
                | ObjSymbolFlags::RelocationIgnore
                | ObjSymbolFlags::Stripped
                | ObjSymbolFlags::NoExport
                | ObjSymbolFlags::NoReloc)
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for ObjSymbolFlagSet {
    fn hash<H>(&self, state: &mut H)
    where H: Hasher {
        self.0.bits().hash(state)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub enum ObjSymbolKind {
    #[default]
    Unknown,
    Function,
    Object,
    Section,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum ObjDataKind {
    #[default]
    Unknown,
    Byte,
    Byte2,
    Byte4,
    Byte8,
    Float,
    Double,
    String,
    ShiftJIS,
    String16,
    StringTable,
    ShiftJISTable,
    String16Table,
    Int,
    Short,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ObjSymbol {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub section: Option<SectionIndex>,
    pub size: u64,
    pub size_known: bool,
    pub flags: ObjSymbolFlagSet,
    pub kind: ObjSymbolKind,
    pub align: Option<u32>,
    pub data_kind: ObjDataKind,
    /// ALF hashes
    pub name_hash: Option<u32>,
    pub demangled_name_hash: Option<u32>,
}

pub type SymbolIndex = u32;

#[derive(Debug, Clone)]
pub struct ObjSymbols {
    obj_kind: ObjKind,
    symbols: Vec<ObjSymbol>,
    symbols_by_address: BTreeMap<u32, Vec<SymbolIndex>>,
    symbols_by_name: HashMap<String, Vec<SymbolIndex>>,
    symbols_by_section: Vec<BTreeMap<u32, Vec<SymbolIndex>>>,
}

impl ObjSymbols {
    pub fn new(obj_kind: ObjKind, symbols: Vec<ObjSymbol>) -> Self {
        let mut symbols_by_address = BTreeMap::<u32, Vec<SymbolIndex>>::new();
        let mut symbols_by_section: Vec<BTreeMap<u32, Vec<SymbolIndex>>> = vec![];
        let mut symbols_by_name = HashMap::<String, Vec<SymbolIndex>>::new();
        for (idx, symbol) in symbols.iter().enumerate() {
            let idx = idx as SymbolIndex;
            symbols_by_address.nested_push(symbol.address as u32, idx);
            if let Some(section_idx) = symbol.section {
                let section_idx = section_idx as usize;
                if section_idx >= symbols_by_section.len() {
                    symbols_by_section.resize_with(section_idx + 1, BTreeMap::new);
                }
                symbols_by_section[section_idx].nested_push(symbol.address as u32, idx);
            } else {
                debug_assert!(
                    symbol.address == 0
                        || symbol.flags.is_common()
                        || obj_kind == ObjKind::Executable,
                    "ABS symbol in relocatable object"
                );
            }
            if !symbol.name.is_empty() {
                symbols_by_name.nested_push(symbol.name.clone(), idx);
            }
        }
        Self { obj_kind, symbols, symbols_by_address, symbols_by_name, symbols_by_section }
    }

    pub fn add(&mut self, in_symbol: ObjSymbol, replace: bool) -> Result<SymbolIndex> {
        let opt = if in_symbol.flags.is_stripped() {
            // Stripped symbols don't overwrite existing symbols
            None
        } else if let Some(section_index) = in_symbol.section {
            self.at_section_address(section_index, in_symbol.address as u32).find(|(_, symbol)| {
                symbol.kind == in_symbol.kind ||
                    // Replace auto symbols with real symbols
                    (symbol.kind == ObjSymbolKind::Unknown && is_auto_symbol(symbol))
            })
        } else if self.obj_kind == ObjKind::Executable {
            // TODO hmmm
            self.iter_abs().find(|(_, symbol)| symbol.name == in_symbol.name)
        } else {
            bail!("ABS symbol in relocatable object: {:?}", in_symbol);
        };
        let target_symbol_idx = if let Some((symbol_idx, existing)) = opt {
            let replace = replace
                // Replace auto symbols with known symbols
                || (is_auto_symbol(existing) && !is_auto_symbol(&in_symbol))
                // Replace lbl_ with jumptable_
                || (is_auto_label(existing) && is_auto_jump_table(&in_symbol));
            let size =
                if existing.size_known && in_symbol.size_known && existing.size != in_symbol.size {
                    // TODO fix this and restore to warning
                    log::debug!(
                        "Conflicting size for {}: was {:#X}, now {:#X}",
                        existing.name,
                        existing.size,
                        in_symbol.size
                    );
                    if replace {
                        in_symbol.size
                    } else {
                        existing.size
                    }
                } else if in_symbol.size_known {
                    in_symbol.size
                } else {
                    existing.size
                };
            if !replace {
                // Not replacing existing symbol, but update size
                if in_symbol.size_known && !existing.size_known {
                    self.replace(symbol_idx, ObjSymbol {
                        size: in_symbol.size,
                        size_known: true,
                        ..existing.clone()
                    })?;
                }
                return Ok(symbol_idx);
            }
            let new_symbol = ObjSymbol {
                name: in_symbol.name,
                demangled_name: in_symbol.demangled_name,
                address: in_symbol.address,
                section: in_symbol.section,
                size,
                size_known: existing.size_known || in_symbol.size != 0,
                flags: ObjSymbolFlagSet(in_symbol.flags.0 | existing.flags.keep_flags()),
                kind: in_symbol.kind,
                align: in_symbol.align.or(existing.align),
                data_kind: match in_symbol.data_kind {
                    ObjDataKind::Unknown => existing.data_kind,
                    kind => kind,
                },
                name_hash: in_symbol.name_hash.or(existing.name_hash),
                demangled_name_hash: in_symbol.demangled_name_hash.or(existing.demangled_name_hash),
            };
            if existing != &new_symbol {
                log::debug!("Replacing {:?} with {:?}", existing, new_symbol);
                self.replace(symbol_idx, new_symbol)?;
            }
            symbol_idx
        } else {
            let target_symbol_idx = self.symbols.len() as SymbolIndex;
            self.add_direct(ObjSymbol {
                name: in_symbol.name,
                demangled_name: in_symbol.demangled_name,
                address: in_symbol.address,
                section: in_symbol.section,
                size: in_symbol.size,
                size_known: in_symbol.size != 0,
                flags: in_symbol.flags,
                kind: in_symbol.kind,
                align: in_symbol.align,
                data_kind: in_symbol.data_kind,
                name_hash: in_symbol.name_hash,
                demangled_name_hash: in_symbol.demangled_name_hash,
            })?;
            target_symbol_idx
        };
        Ok(target_symbol_idx)
    }

    pub fn add_direct(&mut self, in_symbol: ObjSymbol) -> Result<SymbolIndex> {
        let symbol_idx = self.symbols.len() as SymbolIndex;
        self.symbols_by_address.nested_push(in_symbol.address as u32, symbol_idx);
        if let Some(section_idx) = in_symbol.section {
            let section_idx = section_idx as usize;
            if section_idx >= self.symbols_by_section.len() {
                self.symbols_by_section.resize_with(section_idx + 1, BTreeMap::new);
            }
            self.symbols_by_section[section_idx].nested_push(in_symbol.address as u32, symbol_idx);
        } else {
            ensure!(
                in_symbol.address == 0
                    || in_symbol.flags.is_common()
                    || self.obj_kind == ObjKind::Executable,
                "ABS symbol in relocatable object"
            );
        }
        if !in_symbol.name.is_empty() {
            self.symbols_by_name.nested_push(in_symbol.name.clone(), symbol_idx);
        }
        self.symbols.push(in_symbol);
        Ok(symbol_idx)
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols.iter().enumerate().map(|(i, s)| (i as SymbolIndex, s))
    }

    pub fn count(&self) -> SymbolIndex { self.symbols.len() as SymbolIndex }

    pub fn at_section_address(
        &self,
        section_idx: SectionIndex,
        addr: u32,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_section
            .get(section_idx as usize)
            .and_then(|v| v.get(&addr))
            .into_iter()
            .flatten()
            .map(move |&idx| (idx, &self.symbols[idx as usize]))
            // "Stripped" symbols don't actually exist at the address
            .filter(|(_, sym)| !sym.flags.is_stripped())
    }

    pub fn kind_at_section_address(
        &self,
        section_idx: SectionIndex,
        addr: u32,
        kind: ObjSymbolKind,
    ) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        self.at_section_address(section_idx, addr)
            .filter(|(_, sym)| sym.kind == kind)
            .at_most_one()
            .map_err(|e| {
                let symbols = e.map(|(_, s)| s).collect_vec();
                for symbol in symbols {
                    log::error!("{:?}", symbol);
                }
                anyhow!("Multiple symbols of kind {:?} at address {:#010X}", kind, addr)
            })
    }

    // Iterate over all in address ascending order, excluding ABS symbols
    pub fn iter_ordered(&self) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_section
            .iter()
            .flat_map(|v| v.values())
            .flat_map(move |v| v.iter().map(move |u| (*u, &self.symbols[*u as usize])))
    }

    // Iterate over all ABS symbols
    pub fn iter_abs(&self) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        debug_assert!(self.obj_kind == ObjKind::Executable);
        self.symbols_by_address
            .iter()
            .flat_map(|(_, v)| v.iter().map(|&u| (u, &self.symbols[u as usize])))
            .filter(|(_, s)| s.section.is_none())
    }

    // Iterate over range in address ascending order, excluding ABS symbols
    pub fn for_section_range<R>(
        &self,
        section_index: SectionIndex,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)>
    where
        R: RangeBounds<u32> + Clone,
    {
        self.symbols_by_section
            .get(section_index as usize)
            .into_iter()
            .flat_map(move |v| v.range(range.clone()))
            .flat_map(move |(_, v)| v.iter().map(move |u| (*u, &self.symbols[*u as usize])))
    }

    pub fn indexes_for_range<R>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (u32, &[SymbolIndex])>
    where
        R: RangeBounds<u32>,
    {
        // debug_assert!(self.obj_kind == ObjKind::Executable);
        self.symbols_by_address.range(range).map(|(k, v)| (*k, v.as_ref()))
    }

    pub fn for_section(
        &self,
        section_idx: SectionIndex,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_section
            .get(section_idx as usize)
            .into_iter()
            .flat_map(|v| v.values())
            .flat_map(move |v| v.iter().map(move |u| (*u, &self.symbols[*u as usize])))
    }

    pub fn for_name(
        &self,
        name: &str,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_name
            .get(name)
            .into_iter()
            .flat_map(move |v| v.iter().map(move |u| (*u, &self.symbols[*u as usize])))
    }

    pub fn by_name(&self, name: &str) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        let mut iter = self.for_name(name);
        let result = iter.next();
        if let Some((index, symbol)) = result {
            if let Some((other_index, other_symbol)) = iter.next() {
                bail!(
                    "Multiple symbols with name {}: {} {:?} {:#010X} and {} {:?} {:#010X}",
                    name,
                    index,
                    symbol.kind,
                    symbol.address,
                    other_index,
                    other_symbol.kind,
                    other_symbol.address
                );
            }
        }
        Ok(result)
    }

    /// Locate a symbol by name, with optional reference attributes. Example:
    /// `symbol_name!.data:0x1234` will find the symbol named `symbol_name`
    /// in the `.data` section at address `0x1234`.
    pub fn by_ref<'a>(
        &'a self,
        sections: &ObjSections,
        symbol_ref: &str,
    ) -> Result<Option<(SymbolIndex, &'a ObjSymbol)>> {
        if let Some((name, rest)) = symbol_ref.split_once('!') {
            let (section_index, address) = if let Some((section_name, rest)) = rest.split_once(':')
            {
                let section_index = sections
                    .by_name(section_name)?
                    .map(|(idx, _)| idx)
                    .ok_or_else(|| anyhow!("Section not found: {}", section_name))?;
                (Some(section_index), parse_u32(rest)?)
            } else {
                (None, parse_u32(rest)?)
            };
            let mut out = None;
            for (index, symbol) in self.for_name(name) {
                if (section_index.is_none() || symbol.section == section_index)
                    && symbol.address == address as u64
                {
                    ensure!(out.is_none(), "Multiple symbols matched {}", symbol_ref);
                    out = Some((index, symbol));
                }
            }
            Ok(out)
        } else {
            self.by_name(symbol_ref)
        }
    }

    pub fn by_kind(
        &self,
        kind: ObjSymbolKind,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.iter().filter(move |(_, sym)| sym.kind == kind)
    }

    pub fn replace(&mut self, index: SymbolIndex, symbol: ObjSymbol) -> Result<()> {
        let symbol_ref = &mut self.symbols[index as usize];
        ensure!(symbol_ref.address == symbol.address, "Can't modify address with replace_symbol");
        ensure!(symbol_ref.section == symbol.section, "Can't modify section with replace_symbol");
        if symbol_ref.name != symbol.name {
            if !symbol_ref.name.is_empty() {
                self.symbols_by_name.nested_remove(&symbol_ref.name, &index);
            }
            if !symbol.name.is_empty() {
                self.symbols_by_name.nested_push(symbol.name.clone(), index);
            }
        }
        *symbol_ref = symbol;
        Ok(())
    }

    // Try to find a previous sized symbol that encompasses the target
    pub fn for_relocation(
        &self,
        target_addr: SectionAddress,
        reloc_kind: ObjRelocKind,
    ) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        // ensure!(self.obj_kind == ObjKind::Executable);
        let mut result = None;
        for (_addr, symbol_idxs) in self.indexes_for_range(..=target_addr.address).rev() {
            let symbols = symbol_idxs
                .iter()
                .map(|&idx| (idx, &self.symbols[idx as usize]))
                .filter(|(_, sym)| {
                    (sym.section.is_none() || sym.section == Some(target_addr.section))
                        && sym.referenced_by(reloc_kind)
                })
                .collect_vec();
            let Some((symbol_idx, symbol)) = best_match_for_reloc(symbols, reloc_kind) else {
                continue;
            };
            if symbol.address == target_addr.address as u64 {
                result = Some((symbol_idx, symbol));
                break;
            }
            if symbol.size > 0 {
                if symbol.address + symbol.size > target_addr.address as u64 {
                    result = Some((symbol_idx, symbol));
                }
                break;
            }
        }
        Ok(result)
    }

    #[inline]
    pub fn flags(&mut self, idx: SymbolIndex) -> &mut ObjSymbolFlagSet {
        &mut self.symbols[idx as usize].flags
    }
}

impl Index<SymbolIndex> for ObjSymbols {
    type Output = ObjSymbol;

    fn index(&self, index: SymbolIndex) -> &Self::Output { &self.symbols[index as usize] }
}

impl ObjSymbol {
    /// Whether this symbol can be referenced by the given relocation kind.
    pub fn referenced_by(&self, reloc_kind: ObjRelocKind) -> bool {
        if self.flags.is_relocation_ignore() || self.flags.is_stripped() {
            return false;
        }

        if is_linker_generated_label(&self.name) {
            // Linker generated labels will only be referenced by @ha/@h/@l relocations
            return matches!(
                reloc_kind,
                ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Hi | ObjRelocKind::PpcAddr16Lo
            );
        }

        match self.kind {
            ObjSymbolKind::Unknown => true,
            ObjSymbolKind::Function => !matches!(reloc_kind, ObjRelocKind::PpcEmbSda21),
            ObjSymbolKind::Object => {
                // !matches!(reloc_kind, ObjRelocKind::PpcRel14 | ObjRelocKind::PpcRel24)
                true // SADX has bugged relocations that jump from .text to .bss, how awful
            }
            ObjSymbolKind::Section => {
                matches!(
                    reloc_kind,
                    ObjRelocKind::PpcAddr16Ha
                        | ObjRelocKind::PpcAddr16Hi
                        | ObjRelocKind::PpcAddr16Lo
                )
            }
        }
    }
}

pub fn best_match_for_reloc(
    mut symbols: Vec<(SymbolIndex, &ObjSymbol)>,
    reloc_kind: ObjRelocKind,
) -> Option<(SymbolIndex, &ObjSymbol)> {
    if symbols.len() == 1 {
        return symbols.into_iter().next();
    }
    symbols.sort_by_key(|&(_, symbol)| {
        let mut rank = match symbol.kind {
            ObjSymbolKind::Function | ObjSymbolKind::Object => {
                // HACK: These are generally not referenced directly, so reduce their rank
                if matches!(
                    symbol.name.as_str(),
                    "__save_gpr" | "__restore_gpr" | "__save_fpr" | "__restore_fpr"
                ) {
                    return 0;
                }
                match reloc_kind {
                    ObjRelocKind::PpcAddr16Hi
                    | ObjRelocKind::PpcAddr16Ha
                    | ObjRelocKind::PpcAddr16Lo => 1,
                    ObjRelocKind::Absolute
                    | ObjRelocKind::PpcRel24
                    | ObjRelocKind::PpcRel14
                    | ObjRelocKind::PpcEmbSda21 => 2,
                }
            }
            // Label
            ObjSymbolKind::Unknown => match reloc_kind {
                ObjRelocKind::PpcAddr16Hi
                | ObjRelocKind::PpcAddr16Ha
                | ObjRelocKind::PpcAddr16Lo
                    if !symbol.name.starts_with("..") =>
                {
                    3
                }
                _ => 1,
            },
            ObjSymbolKind::Section => -1,
        };
        if symbol.size > 0 {
            rank += 1;
        }
        -rank
    });
    symbols.into_iter().next()
}
