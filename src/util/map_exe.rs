use std::collections::{btree_map, BTreeMap};
use typed_path::Utf8NativePathBuf;
use std::fs::read_to_string;
use std::str::SplitWhitespace;
use anyhow::bail;
use itertools::Itertools;
use crate::analysis::cfa::SectionAddress;
use anyhow::Result;

pub struct ExeMapEntry {
    pub addr: SectionAddress,
    pub symbol: String,
    pub is_function: bool,
}

impl ExeMapEntry {
    pub fn new(addr: SectionAddress, symbol: String, is_function: bool) -> Self {
        ExeMapEntry { addr, symbol, is_function }
    }
}

pub const ADDR_STR: &str = "  Address         Publics by Value              Rva+Base       Lib:Object";

pub fn process_map_exe(map_path: &Utf8NativePathBuf) -> Result<()> {
    println!("map: {}", map_path);

    let mut obj_map: BTreeMap<String, Vec<ExeMapEntry>> = Default::default();
    let mut time_to_read_entries = false;

    for line in read_to_string(map_path).unwrap().lines() {
        // we don't really care to read section layouts, we should've already done so when processing the exe
        if line == ADDR_STR { time_to_read_entries = true; continue; }
        if !time_to_read_entries { continue; }

        // a valid map entry we can parse has the following structure:
        // (sec_index:offset_within_section), (symbol_name), (mem_addr), (f if function, otherwise nothing), (lib:obj names)
        let split: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if split.len() != 4 && split.len() != 5 { continue; }
        if !split[0].contains(":") { continue; }

        let sec_numbers: Vec<&str> = split[0].split(":").collect();
        let sec_idx = sec_numbers[0].parse::<u32>().unwrap();
        let sym_name = split[1].clone();
        // let addr = split[2].parse::<u32>().unwrap();
        let addr = u32::from_str_radix(&split[2].clone(), 16)?;
        let mut is_function = false;
        let mut obj_source = String::new();
        let entry4 = split[3].clone();
        if entry4 == "f" {
            is_function = true;
            obj_source = split[4].clone();
        }
        else {
            obj_source = entry4;
        }

        // obj_map.insert(obj_source, ExeMapEntry::new(SectionAddress::new(sec_idx, addr), sym_name, is_function));
        let exe_entry = ExeMapEntry::new(SectionAddress::new(sec_idx, addr), sym_name, is_function);
        match obj_map.entry(obj_source) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(vec![exe_entry]);
            }
            btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().push(exe_entry);
            }
        }

        // println!("{} ({})", line, num_parts);
    }

    for (obj_source, obj_entries) in obj_map.iter() {
        // println!("Obj {} contains {} entries", obj_source, obj_entries.len());
        if obj_source.contains("Gamepad") {
            println!("Obj {}:", obj_source);
            for entry in obj_entries {
                println!("  {}: {}", entry.addr, entry.symbol);
            }
        }
    }
    Ok(())
}