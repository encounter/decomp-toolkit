use std::collections::{btree_map, BTreeMap, HashMap};
use typed_path::Utf8NativePathBuf;
use std::fs::read_to_string;
use std::str::SplitWhitespace;
use anyhow::bail;
use itertools::Itertools;
use crate::analysis::cfa::SectionAddress;
use anyhow::Result;
use indexmap::IndexMap;
use multimap::MultiMap;
use crate::util::map::{SectionInfo, SymbolEntry, SymbolRef};

// SymbolRef: the symbol name, and the obj it came from

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExeSectionInfo {
    pub name: String,
    pub index: u32,
    pub offset: u32,
    pub size: u32,
}

pub struct ExeSymbolEntry {
    pub addr: SectionAddress,
    pub symbol: String,
    pub unit: String,
    pub is_function: bool,
    pub is_weak: bool, // denoted by the "i" in the symbol flags
    pub is_static: bool,
}

pub struct ExeMapInfo {
    pub entry_point: u32,
    pub sections: Vec<ExeSectionInfo>,
    pub section_symbols: Vec<Vec<ExeSymbolEntry>>,

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
        ExeMapInfo { entry_point: 0, sections: Vec::new(), section_symbols: Vec::new() }
    }

    fn set_entry_point(&mut self, entry_point: u32) { self.entry_point = entry_point; }

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
}

pub const ENTRY_STR: &str = " Preferred load address is ";
pub const SECTION_STR: &str = " Start         Length     Name                   Class";
pub const ADDR_STR: &str = "  Address         Publics by Value              Rva+Base       Lib:Object";
pub const STATIC_SYM_STR: &str = " Static symbols";

pub enum ExeMapState {
    None,
    ReadingSections,
    ReadingSymbols,
    ReadingStaticSymbols
}

pub fn process_map_exe(map_path: &Utf8NativePathBuf) -> Result<ExeMapInfo> {
    println!("map: {}", map_path);

    let mut state = ExeMapState::None;
    let mut exe_map_info = ExeMapInfo::new();
    let mut must_read_syms = true;

    for line in read_to_string(map_path)?.lines() {
        if line.contains(ENTRY_STR) {
            let entry_str = line.split(ENTRY_STR).collect::<Vec<&str>>();
            assert_eq!(entry_str.len(), 2);
            exe_map_info.set_entry_point(u32::from_str_radix(&entry_str[1].clone(), 16)?);
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
                if symbol_parts[1] == "??__Eg_RGBScaledToYUV601@D3D@@YAXXZ" {
                    println!("here");
                }
                // for (idx, part) in symbol_parts.iter().enumerate() {
                //     println!("{}: {}", idx, part);
                // }
                exe_map_info.add_symbol(symbol_parts, true)?;
            }
        }
    }
    Ok(exe_map_info)
}