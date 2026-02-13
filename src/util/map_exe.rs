use std::{
    collections::{btree_map, BTreeMap, HashMap},
    fs::read_to_string,
};

use anyhow::{bail, Result};
use multimap::MultiMap;
use typed_path::Utf8NativePathBuf;

use crate::{
    analysis::cfa::SectionAddress,
    obj::{
        ObjInfo, ObjSectionKind, ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind, ObjUnit,
    },
};

// SymbolRef: the symbol name, and the obj it came from

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExeSectionType {
    Code,
    Data,
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
    pub addr: u32,
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
    pub merged_addrs: Vec<u32>,
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

impl Default for ExeMapInfo {
    fn default() -> Self { Self::new() }
}

impl ExeMapInfo {
    pub fn new() -> Self {
        ExeMapInfo {
            preferred_load_addr: 0,
            sections: Vec::new(),
            section_symbols: Vec::new(),
            merged_addrs: Vec::new(),
        }
    }

    fn set_preferred_load_addr(&mut self, entry_point: u32) {
        self.preferred_load_addr = entry_point;
    }

    fn add_section(&mut self, section: ExeSectionInfo) {
        self.sections.push(section);
        self.section_symbols.push(Vec::new());
    }

    fn get_section_idx(&self, idx: u32, offset: u32) -> Result<usize> {
        for (sec_idx, sec) in self.sections.iter().enumerate() {
            if sec.index == idx && (offset >= sec.offset && offset < (sec.offset + sec.size))
                || (offset >= sec.offset && sec.size == 0 && sec.name == ".xedata")
            {
                return Ok(sec_idx);
            }
        }
        bail!("index {}:{:#X} not found", idx, offset);
    }

    fn add_symbol(&mut self, symbol_parts: Vec<&str>, is_static: bool) -> Result<()> {
        let idx_and_offset = symbol_parts[0].split(":").collect::<Vec<&str>>();
        let sec_idx = u32::from_str_radix(idx_and_offset[0], 16)?;
        let sec_offset = u32::from_str_radix(idx_and_offset[1], 16)?;
        let flags_slice = &symbol_parts[3..symbol_parts.len() - 1];
        let section_symbol_idx = self.get_section_idx(sec_idx, sec_offset)?;

        self.section_symbols.get_mut(section_symbol_idx).unwrap().push(ExeSymbolEntry {
            addr: u32::from_str_radix(symbol_parts[2], 16)?,
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
                    if dupe.symbol.starts_with("__imp_") {
                        imp = Some(dupe.symbol.trim_start_matches("__imp_"));
                    } else {
                        thunk = Some(dupe.symbol.as_str());
                    }
                }

                if let (Some(imp), Some(thunk)) = (imp, thunk) {
                    if imp == thunk {
                        // println!("Unnecessary thunk {} found!", thunk);
                        return Some(thunk.to_string());
                    }
                }
            }
            None
        }

        for entries in self.section_symbols.iter_mut() {
            let mut counts = HashMap::new();
            for entry in entries.iter() {
                *counts.entry(entry.addr).or_insert(0) += 1;
            }

            let mut dupe_map: MultiMap<u32, usize> = Default::default(); // store indices
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
                } else {
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
pub const ADDR_STR: &str =
    "  Address         Publics by Value              Rva+Base       Lib:Object";
pub const STATIC_SYM_STR: &str = " Static symbols";

pub enum ExeMapState {
    None,
    ReadingSections,
    ReadingSymbols,
    ReadingStaticSymbols,
}

pub fn apply_map_file_exe(path: &Utf8NativePathBuf, obj: &mut ObjInfo) -> Result<()> {
    let map_info = process_map_exe(path)?;
    apply_map_exe(map_info, obj)
}

pub fn is_reg_intrinsic(name: &str) -> bool {
    (name.contains("__save") || name.contains("__rest"))
        && (name.contains("gpr") || name.contains("fpr") || name.contains("vmx"))
}

pub fn apply_map_exe(result: ExeMapInfo, obj: &mut ObjInfo) -> Result<()> {
    // apply map symbols to ObjInfo
    for entries in result.section_symbols.iter() {
        for sym in entries {
            // we want to skip imps and save/restore reg intrinsics, since we'll find those ourselves later
            if !sym.symbol.contains("__imp_")
                && !is_reg_intrinsic(&sym.symbol)
                && sym.symbol != "__NLG_Return"
            {
                match obj.sections.at_address(sym.addr) {
                    Ok((sec_idx, sec)) => {
                        let sym_name = if result.merged_addrs.contains(&sym.addr) {
                            format!("merged_{:08X}", sym.addr)
                        } else {
                            sym.symbol.clone()
                        };
                        // if func came from pdata, DO NOT override the size
                        let the_sec_addr = SectionAddress::new(sec_idx, sym.addr);
                        let sym_to_add: ObjSymbol = if obj.pdata_funcs.contains(&the_sec_addr) {
                            ObjSymbol {
                                name: sym_name,
                                address: sym.addr as u64,
                                section: Some(sec_idx),
                                size: obj.known_functions.get(&the_sec_addr).unwrap().unwrap()
                                    as u64,
                                size_known: true,
                                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                                kind: if sec.kind == ObjSectionKind::Code
                                    && sym.symbol != "__NLG_Dispatch"
                                    && sym.symbol != "__NLG_Return"
                                {
                                    ObjSymbolKind::Function
                                } else {
                                    ObjSymbolKind::Object
                                },
                                ..Default::default()
                            }
                        } else {
                            ObjSymbol {
                                name: sym_name,
                                address: sym.addr as u64,
                                section: Some(sec_idx),
                                size: 0,
                                size_known: false, // shoutout to MSVC maps for not providing sizes
                                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                                kind: if sec.kind == ObjSectionKind::Code
                                    && sym.symbol != "__NLG_Dispatch"
                                    && sym.symbol != "__NLG_Return"
                                {
                                    ObjSymbolKind::Function
                                } else {
                                    ObjSymbolKind::Object
                                },
                                ..Default::default()
                            }
                        };
                        obj.add_symbol(sym_to_add, true)?;
                    }
                    // if we couldn't find the section (like maybe it was stripped), just continue on
                    Err(_) => continue,
                };
            }
        }
    }

    fn fix_split_name(orig_name: String) -> String {
        let ret = orig_name.replace(":", "/");
        if orig_name.contains(".obj") {
            ret.replace(".obj", ".cpp")
        }
        // probably an import library
        else {
            // xapilib:xam.xex@21256.0+1861.0, for example
            let parts: Vec<&str> = ret.split(".").collect();
            String::from(parts[0]) + ".cpp"
        }
    }

    // identify split bounds and apply them to ObjInfo
    for (idx, entries) in result.section_symbols.iter().enumerate() {
        if entries.is_empty() {
            continue;
        }

        let section_name = result.sections[idx].name.clone();
        let (_target_sec_idx, target_sec) = match obj.sections.at_address_mut(entries[0].addr) {
            Ok((target_sec_idx, target_sec)) => (target_sec_idx, target_sec),
            Err(_) => continue,
        };
        let section_start = target_sec.address as u32 + result.sections[idx].offset;
        let section_end = section_start + result.sections[idx].size;
        // println!("Section {}: {:#X}-{:#X}", section_name, section_start, section_end);

        // the contiguous, ascending addresses associated with our entries,
        // as well as the objs that have symbols at these addresses
        let sorted_addr_map = {
            let mut ret: BTreeMap<u32, Vec<String>> = BTreeMap::new();
            for entry in entries {
                match ret.entry(entry.addr) {
                    btree_map::Entry::Occupied(mut o) => {
                        o.get_mut().push(entry.unit.clone());
                    }
                    btree_map::Entry::Vacant(v) => {
                        v.insert(vec![entry.unit.clone()]);
                    }
                }
            }
            ret
        };

        // state machine to iterate through our sorted_addr_map and deduce obj bounds
        let mut cur_obj: Option<String> = None;
        let mut cur_start: Option<u32> = None;
        let mut new_splits = BTreeMap::<u32, ObjSplit>::new();
        for (addr, objs) in sorted_addr_map {
            match (&cur_obj, &cur_start) {
                (None, None) => {
                    // if the start addr has multiple objs, we can't be sure which it belongs to...so skip it
                    if objs.len() > 1 {
                        // println!("  Warning! We can't deduce an obj bound for addr 0x{:08X}!", addr);
                        continue;
                    }
                    // else, note our first obj's name and starting addr
                    else {
                        cur_start = Some(addr);
                        cur_obj = Some(objs[0].clone());
                    }
                }
                (Some(obj_name), Some(obj_start)) => {
                    // if there's only one obj belonging to this address
                    if objs.len() == 1 {
                        // check that its obj is our cur_obj
                        // if it's not, we have our obj bounds
                        if objs[0] != *obj_name {
                            // println!("\t{} bounds: 0x{:08X} - 0x{:08X}!", obj_name, obj_start, addr);
                            let tu_name: String = fix_split_name(obj_name.clone());
                            new_splits.insert(*obj_start, ObjSplit {
                                unit: tu_name.clone(),
                                end: addr,
                                align: None,
                                common: false,
                                autogenerated: false,
                                skip: false,
                                // if section_name != the ObjSection's name, we have a subsection somewhere that we wanna note
                                rename: if section_name != target_sec.name {
                                    Some(section_name.clone())
                                } else {
                                    None
                                },
                            });
                            // target_sec.splits.push(*obj_start, ObjSplit {
                            //     unit: tu_name.clone(),
                            //     end: addr,
                            //     align: None,
                            //     common: false,
                            //     autogenerated: false,
                            //     skip: false,
                            //     // if section_name != the ObjSection's name, we have a subsection somewhere that we wanna note
                            //     rename: if section_name != target_sec.name { Some(section_name.clone()) } else { None },
                            // });
                            // // if this TU isn't in the link order, add it
                            // if obj.link_order.iter().find(|&x| x.name == tu_name).is_none() {
                            //     obj.link_order.push(ObjUnit {
                            //         name: tu_name.clone(), autogenerated: false, comment_version: None, order: None
                            //     });
                            // }
                            cur_start = Some(addr);
                            cur_obj = Some(objs[0].clone());
                        }
                    }
                    // if there's multiple objs belonging to this address (code merging moment)
                    else if objs.len() > 1 {
                        // if our current obj name is NOT within this address, we have bounds
                        if !objs.contains(obj_name) {
                            // println!("\t{} bounds: 0x{:08X} - 0x{:08X}!", obj_name, obj_start, addr);
                            let tu_name: String = fix_split_name(obj_name.clone());
                            new_splits.insert(*obj_start, ObjSplit {
                                unit: tu_name.clone(),
                                end: addr,
                                align: None,
                                common: false,
                                autogenerated: false,
                                skip: false,
                                // if section_name != the ObjSection's name, we have a subsection somewhere that we wanna note
                                rename: if section_name != target_sec.name {
                                    Some(section_name.clone())
                                } else {
                                    None
                                },
                            });
                            // target_sec.splits.push(*obj_start, ObjSplit {
                            //     unit: tu_name.clone(),
                            //     end: addr,
                            //     align: None,
                            //     common: false,
                            //     autogenerated: false,
                            //     skip: false,
                            //     // if section_name != the ObjSection's name, we have a subsection somewhere that we wanna note
                            //     rename: if section_name != target_sec.name { Some(section_name.clone()) } else { None },
                            // });
                            // if this TU isn't in the link order, add it
                            // if obj.link_order.iter().find(|&x| x.name == tu_name).is_none() {
                            //     obj.link_order.push(ObjUnit {
                            //         name: tu_name.clone(), autogenerated: false, comment_version: None, order: None
                            //     });
                            // }
                            // if every obj associated with this addr is the same
                            if objs.iter().all(|x| x == &objs[0]) {
                                // then we can infer a known start of a new obj
                                cur_start = Some(addr);
                                cur_obj = Some(objs[0].clone());
                            } else {
                                // println!("  Warning! We can't deduce an obj bound for addr 0x{:08X}!", addr);
                                cur_start = None;
                                cur_obj = None;
                            }
                        }
                    }
                    // every address we've noted down should have at least 1 obj
                    else {
                        unreachable!()
                    }
                }
                _ => unreachable!(),
            }
            // if we've reached the last addr in our collection
            if let (Some(obj_name), Some(obj_start)) = (&cur_obj, &cur_start) {
                if addr == entries.last().unwrap().addr {
                    // then we need to set the end bound to the section's end
                    println!(
                        "\tneed to add last obj: {} (0x{:08X}-0x{:08X})",
                        obj_name, obj_start, section_end
                    );
                    // let tu_name: String = fix_split_name(obj_name.clone());
                    // target_sec.splits.push(*obj_start, ObjSplit {
                    //     unit: tu_name.clone(),
                    //     // FIXME: this should be section_end, but there's currently conflicts between this,
                    //     // and symbol bounds later deduced in detect_objects/detect_strings
                    //     end: section_end,
                    //     align: None,
                    //     common: false,
                    //     autogenerated: false,
                    //     skip: false,
                    //     // if section_name != the ObjSection's name, we have a subsection somewhere that we wanna note
                    //     rename: if section_name != target_sec.name { Some(section_name.clone()) } else { None },
                    // });
                    // // if this TU isn't in the link order, add it
                    // if obj.link_order.iter().find(|&x| x.name == tu_name).is_none() {
                    //     obj.link_order.push(ObjUnit {
                    //         name: tu_name.clone(), autogenerated: false, comment_version: None, order: None
                    //     });
                    // }
                }
            }
        }
        for (start_addr, split) in new_splits {
            let tu_name = split.unit.clone();
            println!("adding split for {} at {:#X}-{:#X}", tu_name, start_addr, split.end);
            if !target_sec.splits.has_split_at(start_addr) {
                target_sec.splits.push(start_addr, split);
            }
            // obj.add_split(target_sec_idx, start_addr, split)?;
            // if this TU isn't in the link order, add it
            if !obj.link_order.iter().any(|x| x.name == tu_name) {
                obj.link_order.push(ObjUnit {
                    name: tu_name.clone(),
                    autogenerated: false,
                    comment_version: None,
                    order: None,
                });
            }
        }
    }
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
            exe_map_info.set_preferred_load_addr(u32::from_str_radix(entry_str[1], 16)?);
        } else if line == SECTION_STR {
            state = ExeMapState::ReadingSections;
            continue;
        } else if line == ADDR_STR {
            state = ExeMapState::ReadingSymbols;
            continue;
        } else if line == STATIC_SYM_STR {
            state = ExeMapState::ReadingStaticSymbols;
            must_read_syms = true;
            continue;
        }

        match state {
            ExeMapState::None => continue,
            ExeMapState::ReadingSections => {
                if line.is_empty() {
                    state = ExeMapState::None;
                } else {
                    let sec_parts = line.split_whitespace().collect::<Vec<&str>>();
                    // [0]: idx:offset, [1]: {size}H, [2]: name, [3]: type (we can ignore this)
                    assert_eq!(sec_parts.len(), 4);
                    let idx_and_offset = sec_parts[0].split(":").collect::<Vec<&str>>();
                    let size_str = sec_parts[1].split("H").collect::<Vec<&str>>();
                    exe_map_info.add_section(ExeSectionInfo {
                        name: String::from(sec_parts[2]),
                        index: u32::from_str_radix(idx_and_offset[0], 16)?,
                        offset: u32::from_str_radix(idx_and_offset[1], 16)?,
                        size: u32::from_str_radix(size_str[0], 16)?,
                        section_type: match sec_parts[3] {
                            "CODE" => ExeSectionType::Code,
                            "DATA" => ExeSectionType::Data,
                            _ => unreachable!(),
                        },
                    });
                }
            }
            ExeMapState::ReadingSymbols => {
                if line.is_empty() {
                    if must_read_syms {
                        must_read_syms = false;
                        continue;
                    } else {
                        state = ExeMapState::None;
                        continue;
                    }
                }
                let symbol_parts = line.split_whitespace().collect::<Vec<&str>>();
                if symbol_parts[0].starts_with("0000:") {
                    continue;
                }
                exe_map_info.add_symbol(symbol_parts, false)?;
            }
            ExeMapState::ReadingStaticSymbols => {
                if line.is_empty() {
                    if must_read_syms {
                        must_read_syms = false;
                        continue;
                    } else {
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
