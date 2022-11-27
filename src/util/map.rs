use std::{
    collections::{btree_map::Entry, BTreeMap, HashMap},
    io::BufRead,
    ops::Range,
};

use anyhow::{Error, Result};
use cwdemangle::{demangle, DemangleOptions};
use lazy_static::lazy_static;
use multimap::MultiMap;
use regex::Regex;
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
    pub unit: String,
    pub address: u32,
    pub size: u32,
    pub section: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SymbolRef {
    pub name: String,
    pub unit: String,
}

#[derive(Default)]
struct SectionOrder {
    symbol_order: Vec<SymbolRef>,
    unit_order: Vec<(String, Vec<String>)>,
}

fn is_code_section(section: &str) -> bool { section == ".text" || section == ".init" }

/// Iterate over the BTreeMap and generate an ordered list of symbols and TUs by address.
fn resolve_section_order(
    address_to_symbol: &BTreeMap<u32, SymbolRef>,
    symbol_entries: &mut HashMap<SymbolRef, SymbolEntry>,
) -> Result<SectionOrder> {
    let mut ordering = SectionOrder::default();

    let mut last_unit = String::new();
    let mut unit_override = String::new();
    let mut last_section = String::new();
    let mut section_unit_idx = 0usize;
    for symbol_ref in address_to_symbol.values() {
        if let Some(symbol) = symbol_entries.get_mut(symbol_ref) {
            if last_unit != symbol.unit {
                unit_override.clear();

                if last_section != symbol.section {
                    ordering.unit_order.push((symbol.section.clone(), vec![]));
                    section_unit_idx = ordering.unit_order.len() - 1;
                    last_section = symbol.section.clone();
                }
                let unit_order = &mut ordering.unit_order[section_unit_idx];
                if unit_order.1.contains(&symbol.unit) {
                    // With -common on, .bss is split into two parts. The TU order repeats
                    // at the end with all globally-deduplicated BSS symbols. Once we detect
                    // a duplicate inside of .bss, we create a new section and start again.
                    // TODO the first entry in .comm *could* be a TU without regular .bss
                    if symbol.section == ".bss" {
                        log::debug!(".comm section detected, duplicate {}", symbol.unit);
                        ordering.unit_order.push((".comm".to_string(), vec![symbol.unit.clone()]));
                        section_unit_idx = ordering.unit_order.len() - 1;
                    } else {
                        // Since the map doesn't contain file paths, it's likely that
                        // a TU name conflict is simply a separate file.
                        // TODO need to resolve and split unit in other sections as well
                        unit_override =
                            format!("{}_{}_{:X}", symbol.unit, symbol.section, symbol.address);
                        log::warn!(
                            "TU order conflict: {} exists multiple times in {}. Renaming to {}.",
                            symbol.unit,
                            symbol.section,
                            unit_override,
                        );
                        unit_order.1.push(unit_override.clone());
                    }
                } else {
                    unit_order.1.push(symbol.unit.clone());
                }
                last_unit = symbol.unit.clone();
            }
            // For ASM-generated objects, notype,local symbols in .text
            // are usually local jump labels, and should be ignored.
            if is_code_section(&symbol.section)
                && symbol.size == 0
                && symbol.kind == SymbolKind::NoType
                && symbol.visibility == SymbolVisibility::Local
            {
                // Being named something other than lbl_* could indicate
                // that it's actually a local function, but let's just
                // make the user resolve that if necessary.
                if !symbol.name.starts_with("lbl_") {
                    log::warn!("Skipping local text symbol {}", symbol.name);
                }
                continue;
            }
            // Guess the symbol type if necessary.
            if symbol.kind == SymbolKind::NoType {
                if is_code_section(&symbol.section) {
                    symbol.kind = SymbolKind::Function;
                } else {
                    symbol.kind = SymbolKind::Object;
                }
            }
            // If we're renaming this TU, replace it in the symbol.
            if !unit_override.is_empty() {
                symbol.unit = unit_override.clone();
            }
            ordering.symbol_order.push(symbol_ref.clone());
        } else {
            return Err(Error::msg(format!("Symbol has address but no entry: {:?}", symbol_ref)));
        }
    }

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
        if (section == ".ctors" || section == ".dtors") && order.len() > 1 {
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
    if !t_sort.is_empty() {
        return Err(Error::msg("Cyclic dependency encountered!"));
    }
    // Sanity check, did we get all TUs in the final order?
    for (_, order) in section_unit_order {
        for unit in order {
            if !global_unit_order.contains(unit) {
                return Err(Error::msg(format!("Failed to find an order for {}", unit)));
            }
        }
    }
    Ok(global_unit_order)
}

lazy_static! {
    static ref LINK_MAP_START: Regex = Regex::new("^Link map of (.*)$").unwrap();
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
}

#[derive(Default)]
pub struct MapEntries {
    pub symbols: HashMap<SymbolRef, SymbolEntry>,
    pub unit_entries: MultiMap<String, SymbolRef>,
    pub entry_references: MultiMap<SymbolRef, SymbolRef>,
    pub entry_referenced_from: MultiMap<SymbolRef, SymbolRef>,
    pub address_to_symbol: BTreeMap<u32, SymbolRef>,
    pub unit_section_ranges: HashMap<String, Range<u32>>,
    pub symbol_order: Vec<SymbolRef>,
    pub unit_order: Vec<(String, Vec<String>)>,
}

pub fn process_map<R: BufRead>(reader: R) -> Result<MapEntries> {
    let mut entries = MapEntries::default();

    let mut symbol_stack = Vec::<SymbolRef>::new();
    let mut current_section = String::new();
    let mut last_name = String::new();
    let mut last_unit = String::new();
    let mut has_link_map = false;
    let mut relative_offset = 0u32;
    let mut last_section_end = 0u32;
    for result in reader.lines() {
        match result {
            Ok(line) => {
                if let Some(captures) = LINK_MAP_START.captures(&line) {
                    log::debug!("Entry point: {}", &captures[1]);
                    has_link_map = true;
                } else if let Some(captures) = LINK_MAP_ENTRY.captures(&line) {
                    if captures["sym"].starts_with('.') {
                        last_name.clear();
                        continue;
                    }
                    let is_duplicate = &captures["sym"] == ">>>";
                    let unit = captures["tu"].trim().to_string();
                    let name = if is_duplicate {
                        if last_name.is_empty() {
                            return Err(Error::msg("Last name empty?"));
                        }
                        last_name.clone()
                    } else {
                        captures["sym"].to_string()
                    };
                    let symbol_ref = SymbolRef { name: name.clone(), unit: unit.clone() };
                    let depth: usize = captures["depth"].parse()?;
                    if depth > symbol_stack.len() {
                        symbol_stack.push(symbol_ref.clone());
                    } else if depth <= symbol_stack.len() {
                        symbol_stack.truncate(depth - 1);
                        symbol_stack.push(symbol_ref.clone());
                    }
                    // println!("Entry: {} ({})", name, tu);
                    let kind = match &captures["type"] {
                        "func" => SymbolKind::Function,
                        "object" => SymbolKind::Object,
                        "section" => SymbolKind::Section,
                        "notype" => SymbolKind::NoType,
                        _ => {
                            return Err(Error::msg(format!(
                                "Unknown symbol type: {}",
                                &captures["type"],
                            )));
                        }
                    };
                    let visibility = match &captures["vis"] {
                        "global" => SymbolVisibility::Global,
                        "local" => SymbolVisibility::Local,
                        "weak" => SymbolVisibility::Weak,
                        _ => {
                            return Err(Error::msg(format!(
                                "Unknown symbol visibility: {}",
                                &captures["vis"],
                            )));
                        }
                    };
                    if !is_duplicate && symbol_stack.len() > 1 {
                        let from = &symbol_stack[symbol_stack.len() - 2];
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
                        let demangled =
                            demangle(&name, &DemangleOptions { omit_empty_parameters: true });
                        entries.symbols.insert(symbol_ref.clone(), SymbolEntry {
                            name: name.clone(),
                            demangled,
                            kind,
                            visibility,
                            unit: unit.clone(),
                            address: 0,
                            size: 0,
                            section: String::new(),
                        });
                        last_name = name.clone();
                        entries.unit_entries.insert(unit, symbol_ref.clone());
                    }
                } else if let Some(captures) = LINK_MAP_ENTRY_GENERATED.captures(&line) {
                    let name = captures["sym"].to_string();
                    let demangled =
                        demangle(&name, &DemangleOptions { omit_empty_parameters: true });
                    let symbol_ref =
                        SymbolRef { name: name.clone(), unit: "[generated]".to_string() };
                    entries.symbols.insert(symbol_ref, SymbolEntry {
                        name,
                        demangled,
                        kind: SymbolKind::NoType,
                        visibility: SymbolVisibility::Global,
                        unit: "[generated]".to_string(),
                        address: 0,
                        size: 0,
                        section: String::new(),
                    });
                } else if line.trim().is_empty()
                    || LINK_MAP_ENTRY_DUPLICATE.is_match(&line)
                    || SECTION_LAYOUT_HEADER.is_match(&line)
                    || EXTERN_SYMBOL.is_match(&line)
                {
                    // Ignore
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    current_section = captures["section"].trim().to_string();
                    last_unit.clear();
                    log::debug!("Processing section layout for {}", current_section);
                } else if let Some(captures) = SECTION_LAYOUT_SYMBOL.captures(&line) {
                    if captures["rom_addr"].trim() == "UNUSED" {
                        continue;
                    }
                    let sym_name = captures["sym"].trim();
                    let tu = captures["tu"].trim();
                    let mut address = u32::from_str_radix(captures["addr"].trim(), 16)?;
                    let mut size = u32::from_str_radix(captures["size"].trim(), 16)?;

                    // For RELs, the each section starts at address 0. For our purposes
                    // we'll create "fake" addresses by simply starting at the end of the
                    // previous section.
                    if last_unit.is_empty() {
                        if address == 0 {
                            relative_offset = last_section_end;
                        } else {
                            relative_offset = 0;
                        }
                    }
                    address += relative_offset;

                    // Section symbol (i.e. ".data") indicates section size for a TU
                    if sym_name == current_section {
                        // Skip empty sections
                        if size == 0 {
                            continue;
                        }
                        let end = address + size;
                        entries.unit_section_ranges.insert(tu.to_string(), address..end);
                        last_unit = tu.to_string();
                        last_section_end = end;
                        continue;
                    }

                    // Otherwise, for ASM-generated objects, the first section symbol in a TU
                    // has the full size of the section.
                    if tu != last_unit {
                        if size == 0 {
                            return Err(Error::msg(format!(
                                "No section size for {} in {}",
                                sym_name, tu
                            )));
                        }
                        let end = address + size;
                        entries.unit_section_ranges.insert(tu.to_string(), address..end);
                        last_unit = tu.to_string();
                        last_section_end = end;

                        // Clear it, so that we guess the "real" symbol size later.
                        size = 0;
                    }

                    // Ignore ...data.0 and similar
                    if sym_name.starts_with("...") {
                        continue;
                    }

                    let symbol_ref = SymbolRef { name: sym_name.to_string(), unit: tu.to_string() };
                    if let Some(symbol) = entries.symbols.get_mut(&symbol_ref) {
                        symbol.address = address;
                        symbol.size = size;
                        symbol.section = current_section.clone();
                        match entries.address_to_symbol.entry(address) {
                            Entry::Vacant(entry) => {
                                entry.insert(symbol_ref.clone());
                            }
                            Entry::Occupied(entry) => {
                                log::warn!(
                                    "Symbol overridden @ {:X} from {} to {} in {}",
                                    symbol.address,
                                    entry.get().name,
                                    sym_name,
                                    tu
                                );
                            }
                        }
                    } else {
                        let visibility = if has_link_map {
                            log::warn!(
                                "Symbol not in link map: {} ({}). Type and visibility unknown.",
                                sym_name,
                                tu,
                            );
                            SymbolVisibility::Local
                        } else {
                            SymbolVisibility::Global
                        };
                        entries.symbols.insert(symbol_ref.clone(), SymbolEntry {
                            name: sym_name.to_string(),
                            demangled: None,
                            kind: SymbolKind::NoType,
                            visibility,
                            unit: tu.to_string(),
                            address,
                            size,
                            section: current_section.clone(),
                        });
                        match entries.address_to_symbol.entry(address) {
                            Entry::Vacant(entry) => {
                                entry.insert(symbol_ref.clone());
                            }
                            Entry::Occupied(entry) => {
                                log::warn!(
                                    "Symbol overridden @ {:X} from {} to {} in {}",
                                    address,
                                    entry.get().name,
                                    sym_name,
                                    tu
                                );
                            }
                        }
                    }
                } else if MEMORY_MAP_HEADER.is_match(&line) {
                    // log::debug!("Done");
                    break;
                } else {
                    todo!("{}", line);
                }
            }
            Err(e) => {
                return Err(Error::from(e));
            }
        }
    }

    let section_order = resolve_section_order(&entries.address_to_symbol, &mut entries.symbols)?;
    entries.symbol_order = section_order.symbol_order;
    entries.unit_order = section_order.unit_order;

    Ok(entries)
}
