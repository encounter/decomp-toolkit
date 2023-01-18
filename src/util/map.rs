use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    hash::Hash,
    io::BufRead,
};

use anyhow::{bail, ensure, Error, Result};
use cwdemangle::{demangle, DemangleOptions};
use lazy_static::lazy_static;
use multimap::MultiMap;
use regex::{Captures, Regex};
use topological_sort::TopologicalSort;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    NoType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolVisibility {
    Global,
    Local,
    Weak,
}

#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub name: String,
    pub demangled: Option<String>,
    pub kind: SymbolKind,
    pub visibility: SymbolVisibility,
    pub unit: Option<String>,
    pub address: u32,
    pub size: u32,
    pub section: String,
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

/// Iterate over the BTreeMap and generate an ordered list of symbols and TUs by address.
fn resolve_section_order(
    address_to_symbol: &BTreeMap<u32, SymbolRef>,
    symbol_entries: &mut HashMap<SymbolRef, SymbolEntry>,
) -> Result<SectionOrder> {
    let mut ordering = SectionOrder::default();

    // let mut last_unit = String::new();
    // let mut last_section = String::new();
    // let mut section_unit_idx = 0usize;
    // for symbol_ref in address_to_symbol.values() {
    //     if let Some(symbol) = symbol_entries.get_mut(symbol_ref) {
    //         if last_unit != symbol.unit {
    //             if last_section != symbol.section {
    //                 ordering.unit_order.push((symbol.section.clone(), vec![]));
    //                 section_unit_idx = ordering.unit_order.len() - 1;
    //                 last_section = symbol.section.clone();
    //             }
    //             let unit_order = &mut ordering.unit_order[section_unit_idx];
    //             if unit_order.1.contains(&symbol.unit) {
    //                 // With -common on, .bss is split into two parts. The TU order repeats
    //                 // at the end with all globally-deduplicated BSS symbols. Once we detect
    //                 // a duplicate inside of .bss, we create a new section and start again.
    //                 // TODO the first entry in .comm *could* be a TU without regular .bss
    //                 if symbol.section == ".bss" {
    //                     log::debug!(".comm section detected, duplicate {}", symbol.unit);
    //                     ordering.unit_order.push((".comm".to_string(), vec![symbol.unit.clone()]));
    //                     section_unit_idx = ordering.unit_order.len() - 1;
    //                 } else {
    //                     bail!(
    //                         "TU order conflict: {} exists multiple times in {}.",
    //                         symbol.unit, symbol.section,
    //                     );
    //                 }
    //             } else {
    //                 unit_order.1.push(symbol.unit.clone());
    //             }
    //             last_unit = symbol.unit.clone();
    //         }
    //         // For ASM-generated objects, notype,local symbols in .text
    //         // are usually local jump labels, and should be ignored.
    //         if is_code_section(&symbol.section)
    //             && symbol.size == 0
    //             && symbol.kind == SymbolKind::NoType
    //             && symbol.visibility == SymbolVisibility::Local
    //         {
    //             // Being named something other than lbl_* could indicate
    //             // that it's actually a local function, but let's just
    //             // make the user resolve that if necessary.
    //             if !symbol.name.starts_with("lbl_") {
    //                 log::warn!("Skipping local text symbol {}", symbol.name);
    //             }
    //             continue;
    //         }
    //         // Guess the symbol type if necessary.
    //         if symbol.kind == SymbolKind::NoType {
    //             if is_code_section(&symbol.section) {
    //                 symbol.kind = SymbolKind::Function;
    //             } else {
    //                 symbol.kind = SymbolKind::Object;
    //             }
    //         }
    //         ordering.symbol_order.push(symbol_ref.clone());
    //     } else {
    //         bail!("Symbol has address but no entry: {symbol_ref:?}");
    //     }
    // }

    for iter in ordering.symbol_order.windows(2) {
        let next_address = symbol_entries.get(&iter[1]).unwrap().address;
        let symbol = symbol_entries.get_mut(&iter[0]).unwrap();
        // For ASM-generated objects, we need to guess the symbol size.
        if symbol.size == 0 {
            symbol.size = next_address - symbol.address;
        }
    }

    Ok(ordering)
}

/// The ordering of TUs inside of each section represents a directed edge in a DAG.
/// We can use a topological sort to determine a valid global TU order.
/// There can be ambiguities, but any solution that satisfies the link order
/// constraints is considered valid.
// TODO account for library ordering
#[allow(dead_code)]
pub fn resolve_link_order(section_unit_order: &[(String, Vec<String>)]) -> Result<Vec<String>> {
    let mut global_unit_order = Vec::<String>::new();
    let mut t_sort = TopologicalSort::<String>::new();
    for (section, order) in section_unit_order {
        let mut order: &[String] = order;
        if matches!(section.as_str(), ".ctors" | ".dtors") && order.len() > 1 {
            // __init_cpp_exceptions.o has symbols that get ordered to the beginning of
            // .ctors and .dtors, so our topological sort would fail if we added them.
            // Always skip the first TU of .ctors and .dtors.
            order = &order[1..];
        }
        for iter in order.windows(2) {
            t_sort.add_dependency(iter[0].clone(), iter[1].clone());
        }
    }
    for unit in &mut t_sort {
        global_unit_order.push(unit);
    }
    // An incomplete topological sort indicates that a cyclic dependency was encountered.
    ensure!(t_sort.is_empty(), "Cyclic dependency encountered!");
    // Sanity check, did we get all TUs in the final order?
    for (_, order) in section_unit_order {
        for unit in order {
            ensure!(global_unit_order.contains(unit), "Failed to find an order for {unit}");
        }
    }
    Ok(global_unit_order)
}

lazy_static! {
    static ref LINK_MAP_START: Regex = Regex::new("^Link map of (?P<entry>.*)$").unwrap();
    static ref LINK_MAP_ENTRY: Regex = Regex::new(
        "^\\s*(?P<depth>\\d+)] (?P<sym>.*) \\((?P<type>.*),(?P<vis>.*)\\) found in (?P<tu>.*)$",
    )
    .unwrap();
    static ref LINK_MAP_ENTRY_GENERATED: Regex =
        Regex::new("^\\s*(?P<depth>\\d+)] (?P<sym>.*) found as linker generated symbol$").unwrap();
    static ref LINK_MAP_ENTRY_DUPLICATE: Regex =
        Regex::new("^\\s*(?P<depth>\\d+)] >>> UNREFERENCED DUPLICATE (?P<sym>.*)$").unwrap();
    static ref SECTION_LAYOUT_START: Regex = Regex::new("^(?P<section>.*) section layout$").unwrap();
    static ref SECTION_LAYOUT_SYMBOL: Regex = Regex::new(
        "^\\s*(?P<rom_addr>[0-9A-Fa-f]+|UNUSED)\\s+(?P<size>[0-9A-Fa-f]+)\\s+(?P<addr>[0-9A-Fa-f]+|\\.{8})\\s+(?P<align>\\d+)?\\s*(?P<sym>.*?)(?:\\s+\\(entry of (?P<entry_of>.*?)\\))?\\s+(?P<tu>.*)$",
    )
    .unwrap();
    static ref SECTION_LAYOUT_HEADER: Regex = Regex::new(
        "^(\\s*Starting\\s+Virtual\\s*|\\s*address\\s+Size\\s+address\\s*|\\s*-----------------------\\s*)$",
    )
    .unwrap();
    static ref MEMORY_MAP_HEADER: Regex = Regex::new("^\\s*Memory map:\\s*$").unwrap();
    static ref EXTERN_SYMBOL: Regex = Regex::new("^\\s*>>> SYMBOL NOT FOUND: (.*)$").unwrap();
    static ref LINKER_SYMBOLS_HEADER: Regex = Regex::new("^\\s*Linker generated symbols:\\s*$").unwrap();
}

#[derive(Default)]
pub struct MapEntries {
    pub entry_point: String,
    pub symbols: HashMap<SymbolRef, SymbolEntry>,
    pub unit_entries: MultiMap<String, SymbolRef>,
    pub entry_references: MultiMap<SymbolRef, SymbolRef>,
    pub entry_referenced_from: MultiMap<SymbolRef, SymbolRef>,
    // pub address_to_symbol: BTreeMap<u32, SymbolRef>,
    // pub unit_section_ranges: HashMap<String, HashMap<String, Range<u32>>>,
    pub symbol_order: Vec<SymbolRef>,
    pub unit_order: Vec<(String, Vec<String>)>,
}

#[derive(Default)]
struct LinkMapState {
    last_name: String,
    symbol_stack: Vec<SymbolRef>,
}

#[derive(Default)]
struct SectionLayoutState {
    current_section: String,
    current_unit: Option<String>,
    units: Vec<(u32, String)>,
    symbols: BTreeMap<u32, Vec<SymbolEntry>>,
    // unit_override: Option<String>,
    // relative_offset: u32,
    // last_unit_start: u32,
    // last_section_end: u32,
    has_link_map: bool,
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
    entries: MapEntries,
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
                    self.entries.entry_point = captures["entry"].to_string();
                    self.switch_state(ProcessMapState::LinkMap(Default::default()))?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::LinkMap(ref mut state) => {
                if let Some(captures) = LINK_MAP_ENTRY.captures(&line) {
                    StateMachine::process_link_map_entry(captures, state, &mut self.entries)?;
                } else if let Some(captures) = LINK_MAP_ENTRY_GENERATED.captures(&line) {
                    StateMachine::process_link_map_generated(captures, state, &mut self.entries)?;
                } else if LINK_MAP_ENTRY_DUPLICATE.is_match(&line) || EXTERN_SYMBOL.is_match(&line)
                {
                    // Ignore
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::SectionLayout(ref mut state) => {
                if let Some(captures) = SECTION_LAYOUT_SYMBOL.captures(&line) {
                    StateMachine::section_layout_entry(captures, state, &mut self.entries)?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    // let last_section_end = state.last_section_end;
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        // last_section_end,
                        ..Default::default()
                    }))?;
                } else if SECTION_LAYOUT_HEADER.is_match(&line) {
                    // Ignore
                } else if MEMORY_MAP_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::MemoryMap => {
                // TODO
                if LINKER_SYMBOLS_HEADER.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                }
            }
            ProcessMapState::LinkerGeneratedSymbols => {
                // TODO
            }
        }
        Ok(())
    }

    fn switch_state(&mut self, new_state: ProcessMapState) -> Result<()> {
        self.end_state()?;
        self.state = new_state;
        Ok(())
    }

    fn end_state(&mut self) -> Result<()> {
        match self.state {
            ProcessMapState::LinkMap { .. } => {
                self.has_link_map = true;
            }
            ProcessMapState::SectionLayout(ref mut state) => {
                StateMachine::end_section_layout(state, &mut self.entries)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn process_link_map_entry(
        captures: Captures,
        state: &mut LinkMapState,
        entries: &mut MapEntries,
    ) -> Result<()> {
        // if captures["sym"].starts_with('.') {
        //     state.last_name.clear();
        //     return Ok(());
        // }
        let is_duplicate = &captures["sym"] == ">>>";
        let unit = captures["tu"].trim().to_string();
        let name = if is_duplicate {
            ensure!(!state.last_name.is_empty(), "Last name empty?");
            state.last_name.clone()
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
            entries.entry_referenced_from.insert(symbol_ref.clone(), from.clone());
            entries.entry_references.insert(from.clone(), symbol_ref.clone());
        }
        let mut should_insert = true;
        if let Some(symbol) = entries.symbols.get(&symbol_ref) {
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
            entries.unit_entries.insert(unit.clone(), symbol_ref.clone());
            should_insert = false;
        }
        if should_insert {
            let demangled = demangle(&name, &DemangleOptions::default());
            entries.symbols.insert(symbol_ref.clone(), SymbolEntry {
                name: name.clone(),
                demangled,
                kind,
                visibility,
                unit: Some(unit.clone()),
                address: 0,
                size: 0,
                section: String::new(),
            });
            state.last_name = name;
            entries.unit_entries.insert(unit, symbol_ref);
        }
        Ok(())
    }

    fn process_link_map_generated(
        captures: Captures,
        _state: &mut LinkMapState,
        entries: &mut MapEntries,
    ) -> Result<()> {
        let name = captures["sym"].to_string();
        let demangled = demangle(&name, &DemangleOptions::default());
        let symbol_ref = SymbolRef { name: name.clone(), unit: None };
        entries.symbols.insert(symbol_ref, SymbolEntry {
            name,
            demangled,
            kind: SymbolKind::NoType,
            visibility: SymbolVisibility::Global,
            unit: None,
            address: 0,
            size: 0,
            section: String::new(),
        });
        Ok(())
    }

    fn end_section_layout(state: &mut SectionLayoutState, entries: &mut MapEntries) -> Result<()> {
        // Set last section size
        // if let Some(last_unit) = state.section_units.last() {
        //     let last_unit = state.unit_override.as_ref().unwrap_or(last_unit);
        //     nested_try_insert(
        //         &mut entries.unit_section_ranges,
        //         last_unit.clone(),
        //         state.current_section.clone(),
        //         state.last_unit_start..state.last_section_end,
        //     )
        //     .with_context(|| {
        //         format!("TU '{}' already exists in section '{}'", last_unit, state.current_section)
        //     })?;
        // }
        Ok(())
    }

    fn section_layout_entry(
        captures: Captures,
        state: &mut SectionLayoutState,
        entries: &mut MapEntries,
    ) -> Result<()> {
        if captures["rom_addr"].trim() == "UNUSED" {
            return Ok(());
        }

        let sym_name = captures["sym"].trim();
        let mut tu = captures["tu"].trim().to_string();
        let mut address = u32::from_str_radix(captures["addr"].trim(), 16)?;
        let mut size = u32::from_str_radix(captures["size"].trim(), 16)?;

        if state.current_unit.as_ref() != Some(&tu) || sym_name == state.current_section {
            state.current_unit = Some(tu.clone());
            state.units.push((address, tu.clone()));
            if sym_name == state.current_section {
                return Ok(());
            }
        }

        let symbol_ref = SymbolRef { name: sym_name.to_string(), unit: Some(tu.clone()) };
        let entry = if let Some(existing) = entries.symbols.get(&symbol_ref) {
            SymbolEntry {
                name: existing.name.clone(),
                demangled: existing.demangled.clone(),
                kind: existing.kind,
                visibility: existing.visibility,
                unit: existing.unit.clone(),
                address,
                size,
                section: state.current_section.clone(),
            }
        } else {
            let visibility = if state.has_link_map {
                log::warn!(
                    "Symbol not in link map: {} ({}). Type and visibility unknown.",
                    sym_name,
                    tu,
                );
                SymbolVisibility::Local
            } else {
                SymbolVisibility::Global
            };
            SymbolEntry {
                name: sym_name.to_string(),
                demangled: None,
                kind: SymbolKind::NoType,
                visibility,
                unit: Some(tu.clone()),
                address,
                size,
                section: state.current_section.clone(),
            }
        };
        match state.symbols.entry(address) {
            btree_map::Entry::Occupied(e) => e.into_mut().push(entry),
            btree_map::Entry::Vacant(e) => {
                e.insert(vec![entry]);
            }
        }
        Ok(())
    }
}

pub fn process_map<R: BufRead>(reader: R) -> Result<MapEntries> {
    let mut state = StateMachine {
        state: ProcessMapState::None,
        entries: Default::default(),
        has_link_map: false,
    };
    for result in reader.lines() {
        match result {
            Ok(line) => state.process_line(line)?,
            Err(e) => return Err(Error::from(e)),
        }
    }
    state.end_state()?;

    let mut entries = state.entries;
    // let section_order = resolve_section_order(&entries.address_to_symbol, &mut entries.symbols)?;
    // entries.symbol_order = section_order.symbol_order;
    // entries.unit_order = section_order.unit_order;
    Ok(entries)
}

#[inline]
fn nested_try_insert<T1, T2, T3>(
    map: &mut HashMap<T1, HashMap<T2, T3>>,
    v1: T1,
    v2: T2,
    v3: T3,
) -> Result<()>
where
    T1: Hash + Eq,
    T2: Hash + Eq,
{
    let map = match map.entry(v1) {
        hash_map::Entry::Occupied(entry) => entry.into_mut(),
        hash_map::Entry::Vacant(entry) => entry.insert(Default::default()),
    };
    match map.entry(v2) {
        hash_map::Entry::Occupied(_) => bail!("Entry already exists"),
        hash_map::Entry::Vacant(entry) => entry.insert(v3),
    };
    Ok(())
}
