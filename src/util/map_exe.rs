use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};
use std::fs::read_to_string;
use std::str::SplitWhitespace;
use anyhow::bail;
use itertools::Itertools;
use crate::analysis::cfa::SectionAddress;
use anyhow::Result;
use indexmap::IndexMap;
use multimap::MultiMap;
use crate::obj::{ObjInfo, ObjReloc};
use crate::util::map::{MapInfo, SectionInfo, SymbolEntry, SymbolRef};

// SymbolRef: the symbol name, and the obj it came from

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExeSectionType {
    Code,
    Data
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExeSectionInfo {
    pub name: String,
    pub index: u32,
    pub offset: u32,
    pub size: u32,
    pub section_type: ExeSectionType,
}

#[derive(Clone)]
pub struct ExeSymbolEntry {
    pub addr: SectionAddress,
    pub symbol: String,
    pub unit: String,
    pub is_function: bool,
    pub is_weak: bool, // denoted by the "i" in the symbol flags
    pub is_static: bool,
}

pub struct ExeMapInfo {
    pub preferred_load_addr: u32,
    // the different sections of the map
    pub sections: Vec<ExeSectionInfo>,
    // the symbols found at each section of the map
    pub section_symbols: Vec<Vec<ExeSymbolEntry>>,
    // the addresses in the map that have more than one symbol for them
    pub merged_addrs: Vec<SectionAddress>,

    // pub entry_point: String,
    // pub unit_entries: MultiMap<String, SymbolRef>,
    // pub entry_references: MultiMap<SymbolRef, SymbolRef>,
    // pub entry_referenced_from: MultiMap<SymbolRef, SymbolRef>,
    // pub unit_references: MultiMap<SymbolRef, String>,
    // pub sections: Vec<SectionInfo>,
    // pub link_map_symbols: HashMap<SymbolRef, SymbolEntry>,
    // pub section_symbols: IndexMap<String, BTreeMap<u32, Vec<SymbolEntry>>>,
    // pub section_units: HashMap<String, Vec<(u32, String)>>,
}

impl ExeMapInfo {
    pub fn new() -> Self {
        ExeMapInfo { preferred_load_addr: 0, sections: Vec::new(), section_symbols: Vec::new(), merged_addrs: Vec::new() }
    }

    fn set_preferred_load_addr(&mut self, entry_point: u32) { self.preferred_load_addr = entry_point; }

    fn add_section(&mut self, section: ExeSectionInfo) {
        self.sections.push(section);
        self.section_symbols.push(Vec::new());
    }

    fn get_section_idx(&self, idx: u32, offset: u32) -> Result<usize> {
        for (sec_idx, sec) in self.sections.iter().enumerate() {
            if sec.index == idx {
                if offset >= sec.offset && offset < (sec.offset + sec.size) {
                    return Ok(sec_idx);
                }
            }
        }
        bail!("index not found");
    }

    fn add_symbol(&mut self, symbol_parts: Vec<&str>, is_static: bool) -> Result<()> {
        let idx_and_offset = symbol_parts[0].split(":").collect::<Vec<&str>>();
        let sec_idx = u32::from_str_radix(&idx_and_offset[0], 16)?;
        let sec_offset = u32::from_str_radix(&idx_and_offset[1], 16)?;
        let flags_slice = &symbol_parts[3..symbol_parts.len() - 1];
        let section_symbol_idx = self.get_section_idx(sec_idx, sec_offset)?;

        self.section_symbols.get_mut(section_symbol_idx).unwrap().push(ExeSymbolEntry {
            addr: SectionAddress::new(sec_idx, u32::from_str_radix(&symbol_parts[2], 16)?),
            symbol: String::from(symbol_parts[1]),
            unit: String::from(*symbol_parts.last().unwrap()),
            is_function: flags_slice.contains(&"f"),
            is_weak: flags_slice.contains(&"i"),
            is_static,
        });
        Ok(())
    }

    pub fn resolve_merged_entries(&mut self) -> Result<()> {
        fn check_for_imp_case(entries: Vec<&ExeSymbolEntry>) -> Option<String> {
            // __imp_{name} and {name} case
            if entries.len() == 2 {
                let mut imp = None;
                let mut thunk = None;

                for dupe in entries {
                    if dupe.symbol.starts_with("__imp_"){
                        imp = Some(dupe.symbol.trim_start_matches("__imp_"));
                    }
                    else {
                        thunk = Some(dupe.symbol.as_str());
                    }
                }

                if let(Some(imp), Some(thunk)) = (imp, thunk) {
                    if imp == thunk {
                        // println!("Unnecessary thunk {} found!", thunk);
                        return Some(thunk.to_string());
                    }
                }
            }
            return None;
        }

        for entries in self.section_symbols.iter_mut() {
            let mut counts = HashMap::new();
            for entry in entries.iter() {
                *counts.entry(entry.addr).or_insert(0) += 1;
            }

            let mut dupe_map: MultiMap<SectionAddress, usize> = Default::default(); // store indices
            for (idx, entry) in entries.iter().enumerate() {
                if counts.get(&entry.addr).copied().unwrap_or(0) > 1 {
                    dupe_map.insert(entry.addr, idx);
                }
            }

            let mut symbols_to_remove: Vec<String> = Vec::new();
            for (addr, indices) in dupe_map.iter_all() {
                let group: Vec<&ExeSymbolEntry> = indices.iter().map(|&i| &entries[i]).collect();

                // print!("{} has entries: ", addr);
                // for dupe in &group {
                //     print!("{} ", dupe.symbol);
                // }
                // println!();

                // resolve imp_Blahs and Blahs that are at the same address
                if let Some(thunk_sym) = check_for_imp_case(group) {
                    symbols_to_remove.push(thunk_sym.to_string());
                }
                else {
                    // add this addr to a list of merged addrs
                    self.merged_addrs.push(*addr);
                }
            }
            entries.retain(|e| !symbols_to_remove.contains(&e.symbol));
        }

        // do something with code merged symbols/units
        // maybe: for an address that has a bunch of code merged symbols, look at the prev and next addrs and see what their units are
        // then wipe out any code merged entry that doesn't belong to those aforementioned units
        Ok(())
    }

}

pub const PREFERRED_LOAD_ADDR_STR: &str = " Preferred load address is ";
pub const SECTION_STR: &str = " Start         Length     Name                   Class";
pub const ADDR_STR: &str = "  Address         Publics by Value              Rva+Base       Lib:Object";
pub const STATIC_SYM_STR: &str = " Static symbols";

pub enum ExeMapState {
    None,
    ReadingSections,
    ReadingSymbols,
    ReadingStaticSymbols
}

pub fn apply_map_file_exe(
    path: &Utf8NativePathBuf,
    obj: &mut ObjInfo,
) -> Result<()> {
    let map_info = process_map_exe(path)?;
    apply_map_exe(map_info, obj)
}

pub fn apply_map_exe(mut result: ExeMapInfo, obj: &mut ObjInfo) -> Result<()> {
    // this is where you'd apply symbols to the ObjInfo,
    // as well as split bounds
    Ok(())
}

pub fn process_map_exe(map_path: &Utf8NativePathBuf) -> Result<ExeMapInfo> {
    println!("map: {}", map_path);

    let mut state = ExeMapState::None;
    let mut exe_map_info = ExeMapInfo::new();
    let mut must_read_syms = true;

    for line in read_to_string(map_path)?.lines() {
        if line.contains(PREFERRED_LOAD_ADDR_STR) {
            let entry_str = line.split(PREFERRED_LOAD_ADDR_STR).collect::<Vec<&str>>();
            assert_eq!(entry_str.len(), 2);
            exe_map_info.set_preferred_load_addr(u32::from_str_radix(&entry_str[1], 16)?);
        }
        else if line == SECTION_STR {
            state = ExeMapState::ReadingSections;
            continue;
        }
        else if line == ADDR_STR {
            state = ExeMapState::ReadingSymbols;
            continue;
        }
        else if line == STATIC_SYM_STR {
            state = ExeMapState::ReadingStaticSymbols;
            must_read_syms = true;
            continue;
        }

        match state {
            ExeMapState::None => continue,
            ExeMapState::ReadingSections => {
                if line == "" { state = ExeMapState::None; }
                else {
                    let sec_parts = line.split_whitespace().collect::<Vec<&str>>();
                    // [0]: idx:offset, [1]: {size}H, [2]: name, [3]: type (we can ignore this)
                    assert_eq!(sec_parts.len(), 4);
                    let idx_and_offset = sec_parts[0].split(":").collect::<Vec<&str>>();
                    let size_str = sec_parts[1].split("H").collect::<Vec<&str>>();
                    exe_map_info.add_section(ExeSectionInfo {
                        name: String::from(sec_parts[2]),
                        index: u32::from_str_radix(&idx_and_offset[0], 16)?,
                        offset: u32::from_str_radix(&idx_and_offset[1], 16)?,
                        size: u32::from_str_radix(&size_str[0], 16)?,
                        section_type: match sec_parts[3] {
                            "CODE" => ExeSectionType::Code,
                            "DATA" => ExeSectionType::Data,
                            _ => unreachable!()
                        }
                    });
                }
            },
            ExeMapState::ReadingSymbols => {
                if line == "" {
                    if must_read_syms {
                        must_read_syms = false;
                        continue;
                    }
                    else {
                        state = ExeMapState::None;
                        continue;
                    }
                }
                let symbol_parts = line.split_whitespace().collect::<Vec<&str>>();
                if symbol_parts[0].starts_with("0000:") { continue; }
                exe_map_info.add_symbol(symbol_parts, false)?;
            }
            ExeMapState::ReadingStaticSymbols => {
                if line == "" {
                    if must_read_syms {
                        must_read_syms = false;
                        continue;
                    }
                    else {
                        state = ExeMapState::None;
                        continue;
                    }
                }
                let symbol_parts = line.split_whitespace().collect::<Vec<&str>>();
                exe_map_info.add_symbol(symbol_parts, true)?;
            }
        }
    }
    exe_map_info.resolve_merged_entries()?;
    Ok(exe_map_info)
}