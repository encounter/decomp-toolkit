#![allow(dead_code)]
#![allow(unused_mut)]
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    io::BufRead,
    mem::{replace, take},
};

use anyhow::{anyhow, bail, Error, Result};
use cwdemangle::{demangle, DemangleOptions};
use flagset::FlagSet;
use indexmap::IndexMap;
use itertools::Itertools;
use multimap::MultiMap;
use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use typed_path::Utf8NativePath;

use crate::{
    obj::{
        section_kind_for_section, ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind,
        ObjSections, ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
        ObjSymbols, ObjUnit, SectionIndex,
    },
    util::nested::NestedVec,
    vfs::open_file,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    NoType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolVisibility {
    Unknown,
    Global,
    Local,
    Weak,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SymbolEntry {
    pub name: String,
    pub demangled: Option<String>,
    pub kind: SymbolKind,
    pub visibility: SymbolVisibility,
    pub unit: Option<String>,
    pub address: u32,
    pub size: u32,
    pub align: Option<u32>,
    pub unused: bool,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SymbolRef {
    pub name: String,
    pub unit: Option<String>,
}

#[derive(Default)]
struct SectionOrder {
    symbol_order: Vec<SymbolRef>,
    unit_order: Vec<(String, Vec<String>)>,
}

#[inline]
fn is_code_section(section: &str) -> bool { matches!(section, ".text" | ".init") }

macro_rules! static_regex {
    ($name:ident, $str:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new($str).unwrap());
    };
}

// Link map
static_regex!(LINK_MAP_START, "^Link map of (?P<entry>.*)$");
static_regex!(
    LINK_MAP_ENTRY,
    "^\\s*(?P<depth>\\d+)] (?P<sym>.*) \\((?P<type>.*),(?P<vis>.*)\\) found in (?P<tu>.*)$"
);
static_regex!(
    LINK_MAP_ENTRY_GENERATED,
    "^\\s*(?P<depth>\\d+)] (?P<sym>.*) found as linker generated symbol$"
);
static_regex!(
    LINK_MAP_ENTRY_DUPLICATE,
    "^\\s*(?P<depth>\\d+)] >>> UNREFERENCED DUPLICATE (?P<sym>.*)$"
);
static_regex!(LINK_MAP_EXTERN_SYMBOL, "^\\s*>>> SYMBOL NOT FOUND: (.*)$");

// Section layout
static_regex!(SECTION_LAYOUT_START, "^(?P<section>.*) section layout$");
static_regex!(
    SECTION_LAYOUT_SYMBOL,
    "^\\s*(?P<rom_addr>[0-9A-Fa-f]+|UNUSED)\\s+(?P<size>[0-9A-Fa-f]+)\\s+(?P<addr>[0-9A-Fa-f]{8}|\\.{8})(?:\\s+(?P<offset>[0-9A-Fa-f]{8}|\\.{8}))?\\s+(?P<align>\\d+)?\\s*(?P<sym>.*?)(?:\\s+\\(entry of (?P<entry_of>.*?)\\))?\\s+(?P<tu>.*)$"
);
static_regex!(
    SECTION_LAYOUT_HEADER,
    "^(\\s*Starting\\s+Virtual\\s*(File\\s*)?|\\s*address\\s+Size\\s+address\\s*(offset\\s*)?|\\s*-----------------------(----------)?\\s*)$"
);

// Memory map
static_regex!(MEMORY_MAP_START, "^\\s*Memory map:\\s*$");
static_regex!(MEMORY_MAP_HEADER, "^(\\s*Starting Size\\s+File\\s*|\\s*address\\s+Offset\\s*)$");
static_regex!(MEMORY_MAP_ENTRY, "^\\s*(?P<section>\\S+)\\s+(?P<addr>[0-9A-Fa-f]+|\\.{0,8})\\s+(?P<size>[0-9A-Fa-f]+|\\.{1,8})\\s+(?P<offset>[0-9A-Fa-f]+|\\.{1,8})\\s*$");

// Linker generated symbols
static_regex!(LINKER_SYMBOLS_START, "^\\s*Linker generated symbols:\\s*$");
static_regex!(LINKER_SYMBOL_ENTRY, "^\\s*(?P<name>\\S+)\\s+(?P<addr>[0-9A-Fa-f]+|\\.{0,8})\\s*$");

#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub file_offset: u32,
}

#[derive(Default)]
pub struct MapInfo {
    pub entry_point: String,
    pub unit_entries: MultiMap<String, SymbolRef>,
    pub entry_references: MultiMap<SymbolRef, SymbolRef>,
    pub entry_referenced_from: MultiMap<SymbolRef, SymbolRef>,
    pub unit_references: MultiMap<SymbolRef, String>,
    pub sections: Vec<SectionInfo>,
    pub link_map_symbols: HashMap<SymbolRef, SymbolEntry>,
    pub section_symbols: IndexMap<String, BTreeMap<u32, Vec<SymbolEntry>>>,
    pub section_units: HashMap<String, Vec<(u32, String)>>,
    // For common BSS inflation correction
    pub common_bss_start: Option<u32>,
    pub mw_comment_version: Option<u8>,
}

impl MapInfo {
    // TODO rework to make this lookup easier
    pub fn get_section_symbol(&self, symbol: &SymbolRef) -> Option<(String, &SymbolEntry)> {
        self.section_symbols.iter().find_map(|(section, m)| {
            m.values()
                .find_map(|v| v.iter().find(|e| e.name == symbol.name && e.unit == symbol.unit))
                .map(|e| (section.clone(), e))
        })
    }
}

#[derive(Default)]
struct LinkMapState {
    last_symbol: Option<SymbolRef>,
    symbol_stack: Vec<SymbolRef>,
}

#[derive(Default)]
struct SectionLayoutState {
    current_section: String,
    units: Vec<(u32, String)>,
    symbols: BTreeMap<u32, Vec<SymbolEntry>>,
    has_link_map: bool,
    last_address: u32,
}

enum ProcessMapState {
    None,
    LinkMap(LinkMapState),
    SectionLayout(SectionLayoutState),
    MemoryMap,
    LinkerGeneratedSymbols,
}

struct StateMachine {
    state: ProcessMapState,
    result: MapInfo,
    has_link_map: bool,
}

impl StateMachine {
    fn process_line(&mut self, line: String) -> Result<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        match &mut self.state {
            ProcessMapState::None => {
                if let Some(captures) = LINK_MAP_START.captures(&line) {
                    self.result.entry_point = captures["entry"].to_string();
                    self.switch_state(ProcessMapState::LinkMap(Default::default()))?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::LinkMap(ref mut state) => {
                if let Some(captures) = LINK_MAP_ENTRY.captures(&line) {
                    StateMachine::process_link_map_entry(captures, state, &mut self.result)?;
                } else if let Some(captures) = LINK_MAP_ENTRY_GENERATED.captures(&line) {
                    StateMachine::process_link_map_generated(captures, state, &mut self.result)?;
                } else if LINK_MAP_ENTRY_DUPLICATE.is_match(&line)
                    || LINK_MAP_EXTERN_SYMBOL.is_match(&line)
                {
                    // Ignore
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::SectionLayout(ref mut state) => {
                if let Some(captures) = SECTION_LAYOUT_SYMBOL.captures(&line) {
                    StateMachine::section_layout_entry(captures, state, &self.result)?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if SECTION_LAYOUT_HEADER.is_match(&line) {
                    // Ignore
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::MemoryMap => {
                if let Some(captures) = MEMORY_MAP_ENTRY.captures(&line) {
                    StateMachine::memory_map_entry(captures, &mut self.result)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                }
            }
            ProcessMapState::LinkerGeneratedSymbols => {
                if let Some(captures) = LINKER_SYMBOL_ENTRY.captures(&line) {
                    StateMachine::linker_symbol_entry(captures, &mut self.result)?;
                }
            }
        }
        Ok(())
    }

    fn switch_state(&mut self, new_state: ProcessMapState) -> Result<()> {
        let old_state = replace(&mut self.state, new_state);
        self.end_state(old_state)?;
        Ok(())
    }

    fn end_state(&mut self, old_state: ProcessMapState) -> Result<()> {
        match old_state {
            ProcessMapState::LinkMap(state) => {
                self.has_link_map = state.last_symbol.is_some();
            }
            ProcessMapState::SectionLayout(state) => {
                StateMachine::end_section_layout(state, &mut self.result)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        // If we didn't find a link map, guess symbol visibility
        if !self.has_link_map {
            let mut symbol_occurrences = HashMap::<String, usize>::new();
            for symbol in self.result.section_symbols.values().flat_map(|v| v.values().flatten()) {
                if symbol.visibility != SymbolVisibility::Local {
                    *symbol_occurrences.entry(symbol.name.clone()).or_default() += 1;
                }
            }

            for symbol in
                self.result.section_symbols.values_mut().flat_map(|v| v.values_mut().flatten())
            {
                if symbol.visibility == SymbolVisibility::Unknown {
                    if symbol.name.starts_with('.') // ...rodata.0
                        || symbol.name.starts_with('@') // @123
                        || symbol.name.starts_with("__sinit")
                        || symbol.name.contains('$') // local$1234
                        || symbol_occurrences.get(&symbol.name).cloned().unwrap_or(0) > 1
                    {
                        symbol.visibility = SymbolVisibility::Local;
                    } else {
                        symbol.visibility = SymbolVisibility::Global;
                    }
                }
            }
        }
        Ok(())
    }

    fn process_link_map_entry(
        captures: Captures,
        state: &mut LinkMapState,
        result: &mut MapInfo,
    ) -> Result<()> {
        let is_duplicate = &captures["sym"] == ">>>";
        let unit = captures["tu"].trim().to_string();
        let name = if is_duplicate {
            let Some(last_symbol) = &state.last_symbol else {
                bail!("Last symbol empty?");
            };
            last_symbol.name.clone()
        } else {
            captures["sym"].to_string()
        };
        let symbol_ref = SymbolRef { name: name.clone(), unit: Some(unit.clone()) };
        let depth: usize = captures["depth"].parse()?;
        if depth > state.symbol_stack.len() {
            state.symbol_stack.push(symbol_ref.clone());
        } else if depth <= state.symbol_stack.len() {
            state.symbol_stack.truncate(depth - 1);
            state.symbol_stack.push(symbol_ref.clone());
        }
        // println!("Entry: {} ({})", name, tu);
        let kind = match &captures["type"] {
            "func" => SymbolKind::Function,
            "object" => SymbolKind::Object,
            "section" => SymbolKind::Section,
            "notype" => SymbolKind::NoType,
            kind => bail!("Unknown symbol type: {kind}"),
        };
        let visibility = match &captures["vis"] {
            "global" => SymbolVisibility::Global,
            "local" => SymbolVisibility::Local,
            "weak" => SymbolVisibility::Weak,
            visibility => bail!("Unknown symbol visibility: {visibility}"),
        };
        if !is_duplicate && state.symbol_stack.len() > 1 {
            let from = &state.symbol_stack[state.symbol_stack.len() - 2];
            result.entry_referenced_from.insert(symbol_ref.clone(), from.clone());
            result.entry_references.insert(from.clone(), symbol_ref.clone());
        }
        result.unit_references.insert(
            if is_duplicate {
                state.last_symbol.as_ref().unwrap().clone()
            } else {
                symbol_ref.clone()
            },
            unit.clone(),
        );
        let mut should_insert = true;
        if let Some(symbol) = result.link_map_symbols.get(&symbol_ref) {
            if symbol.kind != kind {
                log::warn!(
                    "Kind mismatch for {}: was {:?}, now {:?}",
                    symbol.name,
                    symbol.kind,
                    kind
                );
            }
            if symbol.visibility != visibility {
                log::warn!(
                    "Visibility mismatch for {}: was {:?}, now {:?}",
                    symbol.name,
                    symbol.visibility,
                    visibility
                );
            }
            result.unit_entries.insert(unit.clone(), symbol_ref.clone());
            should_insert = false;
        }
        if should_insert {
            let demangled = demangle(&name, &DemangleOptions::default());
            result.link_map_symbols.insert(symbol_ref.clone(), SymbolEntry {
                name: name.clone(),
                demangled,
                kind,
                visibility,
                unit: Some(unit.clone()),
                address: 0,
                size: 0,
                align: None,
                unused: false,
            });
            if !is_duplicate {
                state.last_symbol = Some(symbol_ref.clone());
            }
            result.unit_entries.insert(unit, symbol_ref);
        }
        Ok(())
    }

    fn process_link_map_generated(
        captures: Captures,
        _state: &mut LinkMapState,
        result: &mut MapInfo,
    ) -> Result<()> {
        let name = captures["sym"].to_string();
        let demangled = demangle(&name, &DemangleOptions::default());
        let symbol_ref = SymbolRef { name: name.clone(), unit: None };
        result.link_map_symbols.insert(symbol_ref, SymbolEntry {
            name,
            demangled,
            kind: SymbolKind::NoType,
            visibility: SymbolVisibility::Global,
            unit: None,
            address: 0,
            size: 0,
            align: None,
            unused: false,
        });
        Ok(())
    }

    fn end_section_layout(mut state: SectionLayoutState, entries: &mut MapInfo) -> Result<()> {
        // Check for duplicate TUs and common BSS
        let mut existing = HashSet::new();
        for (addr, unit) in state.units.iter().dedup_by(|(_, a), (_, b)| a == b) {
            if existing.contains(unit) {
                if state.current_section == ".bss" {
                    if entries.common_bss_start.is_none() {
                        log::warn!("Assuming common BSS start @ {:#010X} ({})", addr, unit);
                        log::warn!("Please verify and set common_start in config.yml");
                        entries.common_bss_start = Some(*addr);
                    }
                } else {
                    log::error!(
                        "Duplicate TU in {}: {} @ {:#010X}",
                        state.current_section,
                        unit,
                        addr
                    );
                    log::error!("Please rename the TUs manually to avoid conflicts");
                }
            } else {
                existing.insert(unit.clone());
            }
        }

        // Perform common BSS inflation correction
        // https://github.com/encounter/dtk-template/blob/main/docs/common_bss.md#inflation-bug
        let check_common_bss_inflation = state.current_section == ".bss"
            && entries.common_bss_start.is_some()
            && matches!(entries.mw_comment_version, Some(n) if n < 11);
        if check_common_bss_inflation {
            log::info!("Checking for common BSS inflation...");
            let common_bss_start = entries.common_bss_start.unwrap();

            // Correct address for unused common BSS symbols that are first in a TU
            let mut symbols_iter = state.symbols.iter_mut().peekable();
            let mut last_unit = None;
            let mut add_to_next = vec![];
            while let Some((_, symbols)) = symbols_iter.next() {
                let next_addr = if let Some((&next_addr, _)) = symbols_iter.peek() {
                    next_addr
                } else {
                    u32::MAX
                };
                let mut to_add = take(&mut add_to_next);
                symbols.retain(|e| {
                    if e.address >= common_bss_start && e.unused && e.unit != last_unit {
                        log::debug!(
                            "Updating address for {} @ {:#010X} to {:#010X}",
                            e.name,
                            e.address,
                            next_addr
                        );
                        let mut e = e.clone();
                        e.address = next_addr;
                        add_to_next.push(e);
                        return false;
                    }
                    if !e.unused {
                        last_unit.clone_from(&e.unit);
                    }
                    true
                });
                to_add.extend(take(symbols));
                *symbols = to_add;
            }

            // Correct size for common BSS symbols that are first in a TU (inflated)
            let mut unit_iter = state
                .units
                .iter()
                .skip_while(|&&(addr, _)| addr < common_bss_start)
                .dedup_by(|&(_, a), &(_, b)| a == b)
                .peekable();
            while let Some((start_addr, unit)) = unit_iter.next() {
                let unit_symbols = if let Some(&&(end_addr, _)) = unit_iter.peek() {
                    state.symbols.range(*start_addr..end_addr).collect_vec()
                } else {
                    state.symbols.range(*start_addr..).collect_vec()
                };
                let mut symbol_iter = unit_symbols.iter().flat_map(|(_, v)| *v);
                let Some(first_symbol) = symbol_iter.next() else { continue };
                let first_addr = first_symbol.address;
                let mut remaining_size = symbol_iter.map(|e| e.size).sum::<u32>();
                if remaining_size == 0 {
                    continue;
                }
                if first_symbol.size > remaining_size {
                    let new_size = first_symbol.size - remaining_size;
                    log::info!(
                        "Correcting size for {} ({}) @ {:#010X} ({:#X} -> {:#X})",
                        first_symbol.name,
                        unit,
                        first_addr,
                        first_symbol.size,
                        new_size
                    );
                    state.symbols.get_mut(&first_addr).unwrap().iter_mut().next().unwrap().size =
                        new_size;
                } else {
                    log::warn!(
                        "Inflated size not detected for {} ({}) @ {:#010X} ({} <= {})",
                        first_symbol.name,
                        unit,
                        first_addr,
                        first_symbol.size,
                        remaining_size
                    );
                }
            }
        }

        if !state.symbols.is_empty() {
            // Remove "unused" symbols
            for symbols in state.symbols.values_mut() {
                symbols.retain(|e| {
                    !e.unused ||
                        // Except for unused common BSS symbols needed to match the inflated size
                        (check_common_bss_inflation && e.address >= entries.common_bss_start.unwrap())
                });
            }
            entries.section_symbols.insert(state.current_section.clone(), state.symbols);
        }
        if !state.units.is_empty() {
            entries.section_units.insert(state.current_section.clone(), state.units);
        }
        Ok(())
    }

    fn section_layout_entry(
        captures: Captures,
        state: &mut SectionLayoutState,
        result: &MapInfo,
    ) -> Result<()> {
        let sym_name = captures["sym"].trim();
        if sym_name == "*fill*" {
            return Ok(());
        }

        let tu = captures["tu"].trim().to_string();
        if tu == "*fill*" || tu == "Linker Generated Symbol File" {
            return Ok(());
        }
        let is_new_tu = match state.units.last() {
            None => true,
            Some((_, name)) => name != &tu,
        };

        let (address, unused) = if captures["rom_addr"].trim() == "UNUSED" {
            // Addresses for unused symbols that _start_ a TU
            // are corrected in end_section_layout
            (state.last_address, true)
        } else {
            let address = u32::from_str_radix(captures["addr"].trim(), 16)?;
            state.last_address = address;
            (address, false)
        };
        let size = u32::from_str_radix(captures["size"].trim(), 16)?;
        let align = captures.name("align").and_then(|m| m.as_str().trim().parse::<u32>().ok());

        if is_new_tu || sym_name == state.current_section {
            if !unused {
                state.units.push((address, tu.clone()));
            }
            if sym_name == state.current_section {
                return Ok(());
            }
        }

        let symbol_ref = SymbolRef { name: sym_name.to_string(), unit: Some(tu.clone()) };
        let entry = if let Some(existing) = result.link_map_symbols.get(&symbol_ref) {
            SymbolEntry {
                name: existing.name.clone(),
                demangled: existing.demangled.clone(),
                kind: existing.kind,
                visibility: existing.visibility,
                unit: existing.unit.clone(),
                address,
                size,
                align,
                unused,
            }
        } else {
            let mut visibility = if state.has_link_map && !unused {
                log::warn!(
                    "Symbol not in link map: {} ({}). Type and visibility unknown.",
                    sym_name,
                    tu,
                );
                SymbolVisibility::Local
            } else {
                SymbolVisibility::Unknown
            };
            let kind = if sym_name == state.current_section {
                SymbolKind::Section
            } else if size > 0 {
                if is_code_section(&state.current_section) {
                    SymbolKind::Function
                } else {
                    SymbolKind::Object
                }
            } else {
                SymbolKind::NoType
            };
            SymbolEntry {
                name: sym_name.to_string(),
                demangled: None,
                kind,
                visibility,
                unit: Some(tu.clone()),
                address,
                size,
                align,
                unused,
            }
        };
        state.symbols.nested_push(address, entry);
        Ok(())
    }

    fn memory_map_entry(captures: Captures, entries: &mut MapInfo) -> Result<()> {
        let section = &captures["section"];
        let addr_str = &captures["addr"];
        if addr_str.is_empty() {
            // Stripped from DOL
            return Ok(());
        }
        let address = u32::from_str_radix(addr_str, 16)?;
        let size = u32::from_str_radix(&captures["size"], 16)?;
        let file_offset = u32::from_str_radix(&captures["offset"], 16)?;
        // log::info!("Memory map entry: {section} {address:#010X} {size:#010X} {file_offset:#010X}");
        entries.sections.push(SectionInfo {
            name: section.to_string(),
            address,
            size,
            file_offset,
        });
        Ok(())
    }

    fn linker_symbol_entry(captures: Captures, result: &mut MapInfo) -> Result<()> {
        let name = &captures["name"];
        let address = u32::from_str_radix(&captures["addr"], 16)?;
        if address == 0 {
            return Ok(());
        }

        let symbol_ref = SymbolRef { name: name.to_string(), unit: None };
        if let Some(existing) = result.link_map_symbols.get_mut(&symbol_ref) {
            existing.address = address;
        } else {
            result.link_map_symbols.insert(symbol_ref, SymbolEntry {
                name: name.to_string(),
                demangled: demangle(name, &DemangleOptions::default()),
                kind: SymbolKind::NoType,
                visibility: SymbolVisibility::Global,
                unit: None,
                address,
                size: 0,
                align: None,
                unused: false,
            });
        };
        Ok(())
    }
}

pub fn process_map<R>(
    reader: &mut R,
    common_bss_start: Option<u32>,
    mw_comment_version: Option<u8>,
) -> Result<MapInfo>
where
    R: BufRead + ?Sized,
{
    let mut sm = StateMachine {
        state: ProcessMapState::None,
        result: MapInfo { common_bss_start, mw_comment_version, ..Default::default() },
        has_link_map: false,
    };
    for result in reader.lines() {
        match result {
            Ok(line) => sm.process_line(line)?,
            Err(e) => return Err(Error::from(e)),
        }
    }
    let state = replace(&mut sm.state, ProcessMapState::None);
    sm.end_state(state)?;
    sm.finalize()?;
    Ok(sm.result)
}

pub fn apply_map_file(
    path: &Utf8NativePath,
    obj: &mut ObjInfo,
    common_bss_start: Option<u32>,
    mw_comment_version: Option<u8>,
) -> Result<()> {
    let mut file = open_file(path, true)?;
    let info = process_map(file.as_mut(), common_bss_start, mw_comment_version)?;
    apply_map(info, obj)
}

const DEFAULT_REL_SECTIONS: &[&str] =
    &[".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss"];

fn normalize_section_name(name: &str) -> &str {
    match name {
        ".extabindex" => "extabindex",
        ".extab" => "extab",
        _ => name,
    }
}

pub fn apply_map(mut result: MapInfo, obj: &mut ObjInfo) -> Result<()> {
    if result.sections.is_empty() && obj.kind == ObjKind::Executable {
        log::warn!("Memory map section missing, attempting to recreate");
        for (section_name, symbol_map) in &result.section_symbols {
            let mut address = u32::MAX;
            let mut size = 0;
            for symbol_entry in symbol_map.values().flatten() {
                if symbol_entry.address < address {
                    address = symbol_entry.address;
                }
                if symbol_entry.address + symbol_entry.size > address + size {
                    size = symbol_entry.address + symbol_entry.size - address;
                }
            }
            log::info!("Recreated section {} @ {:#010X} ({:#X})", section_name, address, size);
            result.sections.push(SectionInfo {
                name: normalize_section_name(section_name).to_string(),
                address,
                size,
                file_offset: 0,
            });
        }
    }

    for (section_index, section) in obj.sections.iter_mut() {
        let opt = if obj.kind == ObjKind::Executable {
            result.sections.iter().find(|s| {
                // Slightly fuzzy match for postprocess/broken maps (TP, SMG)
                s.address >= section.address as u32
                    && (s.address + s.size) <= (section.address + section.size) as u32
            })
        } else {
            result.sections.iter().filter(|s| s.size > 0).nth(section_index as usize)
        };
        if let Some(info) = opt {
            if section.section_known && section.name != info.name {
                log::warn!("Section mismatch: was {}, map says {}", section.name, info.name);
            }
            if section.address != info.address as u64 {
                log::warn!(
                    "Section address mismatch: was {:#010X}, map says {:#010X}",
                    section.address,
                    info.address
                );
            }
            if section.size != info.size as u64 {
                log::warn!(
                    "Section size mismatch: was {:#X}, map says {:#X}",
                    section.size,
                    info.size
                );
            }
            section.rename(info.name.clone())?;
        } else {
            log::warn!("Section {} @ {:#010X} not found in map", section.name, section.address);
            if obj.kind == ObjKind::Relocatable {
                let new_name = match section.kind {
                    ObjSectionKind::Code => {
                        if section.elf_index == 0 {
                            ".init"
                        } else {
                            ".text"
                        }
                    }
                    ObjSectionKind::Data | ObjSectionKind::ReadOnlyData => {
                        if section.elf_index == 4 {
                            if result.section_symbols.get(".rodata").is_some_and(|m| !m.is_empty())
                            {
                                ".rodata"
                            } else {
                                ".data"
                            }
                        } else if let Some(section_name) =
                            DEFAULT_REL_SECTIONS.get(section.elf_index as usize)
                        {
                            section_name
                        } else {
                            ".data"
                        }
                    }
                    ObjSectionKind::Bss => ".bss",
                };
                log::warn!("Defaulting to {}", new_name);
                section.rename(new_name.to_string())?;
            }
        }
    }

    // If every symbol the map has alignment 4, it's likely bogus
    let bogus_alignment =
        result.section_symbols.values().flatten().flat_map(|(_, m)| m).all(|s| s.align == Some(4));
    if bogus_alignment {
        log::warn!("Bogus alignment detected, ignoring");
    }

    // Add section symbols
    for (section_name, symbol_map) in &result.section_symbols {
        if section_name == ".dead" {
            continue;
        }
        let section_name = normalize_section_name(section_name);
        let (section_index, _) = obj
            .sections
            .by_name(section_name)?
            .ok_or_else(|| anyhow!("Failed to locate section {section_name} from map"))?;
        for symbol_entry in symbol_map.values().flatten() {
            add_symbol(obj, symbol_entry, Some(section_index), bogus_alignment)?;
        }
    }

    // Add absolute symbols
    // TODO
    // for symbol_entry in result.link_map_symbols.values().filter(|s| s.unit.is_none()) {
    //     add_symbol(obj, symbol_entry, None)?;
    // }

    // Add splits
    for (section_name, unit_order) in &result.section_units {
        if section_name == ".dead" {
            continue;
        }
        let section_name = normalize_section_name(section_name);
        let (_, section) = obj
            .sections
            .iter_mut()
            .find(|(_, s)| s.name == *section_name)
            .ok_or_else(|| anyhow!("Failed to locate section '{}'", section_name))?;
        let mut iter = unit_order.iter().peekable();
        while let Some((addr, unit)) = iter.next() {
            let next = iter
                .peek()
                .map(|(addr, _)| *addr)
                .unwrap_or_else(|| (section.address + section.size) as u32);
            let common = section_name == ".bss"
                && matches!(result.common_bss_start, Some(start) if *addr >= start);
            let unit = unit.replace(' ', "/");

            // Disable mw_comment_version for assembly units
            if unit.ends_with(".s") && !obj.link_order.iter().any(|u| u.name == unit) {
                obj.link_order.push(ObjUnit {
                    name: unit.clone(),
                    autogenerated: false,
                    comment_version: Some(0),
                    order: None,
                });
            }

            section.splits.push(*addr, ObjSplit {
                unit,
                end: next,
                align: None,
                common,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
    }
    Ok(())
}

pub fn create_obj(result: &MapInfo) -> Result<ObjInfo> {
    let sections = result
        .sections
        .iter()
        .map(|s| {
            let name = s.name.clone();
            let address = s.address as u64;
            let size = s.size as u64;
            let file_offset = s.file_offset as u64;
            let kind = section_kind_for_section(&name).unwrap_or(ObjSectionKind::ReadOnlyData);
            ObjSection {
                name,
                kind,
                address,
                size,
                data: vec![],
                align: 0,
                elf_index: 0,
                relocations: Default::default(),
                virtual_address: None,
                file_offset,
                section_known: true,
                splits: Default::default(),
            }
        })
        .collect();
    let mut obj = ObjInfo {
        kind: ObjKind::Executable,
        architecture: ObjArchitecture::PowerPc,
        name: "".to_string(),
        symbols: ObjSymbols::new(ObjKind::Executable, vec![]),
        sections: ObjSections::new(ObjKind::Executable, sections),
        entry: None, // TODO result.entry_point
        mw_comment: None,
        split_meta: None,
        sda2_base: None,
        sda_base: None,
        stack_address: None,
        stack_end: None,
        db_stack_addr: None,
        arena_lo: None,
        arena_hi: None,
        link_order: vec![],
        blocked_relocation_sources: Default::default(),
        blocked_relocation_targets: Default::default(),
        known_functions: Default::default(),
        pdata_funcs: Default::default(),
        module_id: 0,
        unresolved_relocations: vec![],
    };

    // If every symbol the map has alignment 4, it's likely bogus
    let bogus_alignment =
        result.section_symbols.values().flatten().flat_map(|(_, m)| m).all(|s| s.align == Some(4));
    if bogus_alignment {
        log::warn!("Bogus alignment detected, ignoring");
    }

    // Add section symbols
    for (section_name, symbol_map) in &result.section_symbols {
        let (section_index, _) = obj
            .sections
            .by_name(section_name)?
            .ok_or_else(|| anyhow!("Failed to locate section {section_name} from map"))?;
        for symbol_entry in symbol_map.values().flatten() {
            add_symbol(&mut obj, symbol_entry, Some(section_index), bogus_alignment)?;
        }
    }

    // Add splits
    for (section_name, unit_order) in &result.section_units {
        let (_, section) = obj
            .sections
            .iter_mut()
            .find(|(_, s)| s.name == *section_name)
            .ok_or_else(|| anyhow!("Failed to locate section '{}'", section_name))?;
        let mut iter = unit_order.iter().peekable();
        while let Some((addr, unit)) = iter.next() {
            let next = iter
                .peek()
                .map(|(addr, _)| *addr)
                .unwrap_or_else(|| (section.address + section.size) as u32);
            let common = section_name == ".bss"
                && matches!(result.common_bss_start, Some(start) if *addr >= start);
            let unit = unit.replace(' ', "/");

            // Disable mw_comment_version for assembly units
            if unit.ends_with(".s") && !obj.link_order.iter().any(|u| u.name == unit) {
                obj.link_order.push(ObjUnit {
                    name: unit.clone(),
                    autogenerated: false,
                    comment_version: Some(0),
                    order: None,
                });
            }

            section.splits.push(*addr, ObjSplit {
                unit,
                end: next,
                align: None,
                common,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
    }
    Ok(obj)
}

fn add_symbol(
    obj: &mut ObjInfo,
    symbol_entry: &SymbolEntry,
    section: Option<SectionIndex>,
    ignore_alignment: bool,
) -> Result<()> {
    let demangled_name = demangle(&symbol_entry.name, &DemangleOptions::default());
    let mut flags: FlagSet<ObjSymbolFlags> = match symbol_entry.visibility {
        SymbolVisibility::Unknown => Default::default(),
        SymbolVisibility::Global => ObjSymbolFlags::Global.into(),
        SymbolVisibility::Local => ObjSymbolFlags::Local.into(),
        SymbolVisibility::Weak => ObjSymbolFlags::Weak.into(),
    };
    // TODO move somewhere common
    if symbol_entry.name.starts_with("..") {
        flags |= ObjSymbolFlags::Exported;
    }
    if symbol_entry.unused {
        flags |= ObjSymbolFlags::Stripped;
    }
    obj.add_symbol(
        ObjSymbol {
            name: symbol_entry.name.clone(),
            demangled_name,
            address: symbol_entry.address as u64,
            section,
            size: symbol_entry.size as u64,
            size_known: symbol_entry.size != 0,
            flags: ObjSymbolFlagSet(flags),
            kind: match symbol_entry.kind {
                SymbolKind::Function => ObjSymbolKind::Function,
                SymbolKind::Object => ObjSymbolKind::Object,
                SymbolKind::Section => ObjSymbolKind::Section,
                SymbolKind::NoType => ObjSymbolKind::Unknown,
            },
            align: if ignore_alignment { None } else { symbol_entry.align },
            ..Default::default()
        },
        true,
    )?;
    Ok(())
}
