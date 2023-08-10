use std::path::PathBuf;

use anyhow::{bail, Result};
use itertools::Itertools;

use crate::obj::ObjInfo;

#[inline]
const fn align_up(value: u32, align: u32) -> u32 { (value + (align - 1)) & !(align - 1) }

pub fn generate_ldscript(obj: &ObjInfo, auto_force_files: bool) -> Result<String> {
    let origin = obj.sections.iter().map(|s| s.address).min().unwrap();
    let stack_size = match (obj.stack_address, obj.stack_end) {
        (Some(stack_address), Some(stack_end)) => stack_address - stack_end,
        _ => 65535, // default
    };

    // Guess section alignment
    let mut alignments = Vec::with_capacity(obj.sections.len());
    let mut last_section_end = origin as u32;
    for section in &obj.sections {
        let section_start = section.address as u32;
        let mut align = 0x20;
        while align_up(last_section_end, align) < section_start {
            align = (align + 1).next_power_of_two();
        }
        if align_up(last_section_end, align) != section_start {
            bail!(
                "Couldn't determine alignment for section '{}' ({:#010X} -> {:#010X})",
                section.name,
                last_section_end,
                section_start
            );
        }
        last_section_end = section_start + section.size as u32;
        alignments.push(align);
    }

    let section_defs = obj
        .sections
        .iter()
        .zip(alignments)
        .map(|(s, align)| format!("{} ALIGN({:#X}):{{}}", s.name, align))
        .join("\n        ");

    let mut force_files = Vec::with_capacity(obj.link_order.len());
    for unit in &obj.link_order {
        let obj_path = obj_path_for_unit(&unit.name);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let mut force_active = vec![];
    for symbol in obj.symbols.iter() {
        if symbol.flags.is_force_active() && symbol.flags.is_global() {
            force_active.push(symbol.name.clone());
        }
    }

    // Hack to handle missing .sbss2 section... what's the proper way?
    let last_section_name = obj.sections.last().unwrap().name.clone();
    let last_section_symbol = format!("_f_{}", last_section_name.trim_start_matches('.'));

    let mut out = include_str!("../../assets/ldscript.lcf")
        .replace("$ORIGIN", &format!("{:#X}", origin))
        .replace("$SECTIONS", &section_defs)
        .replace("$LAST_SECTION_SYMBOL", &last_section_symbol)
        .replace("$LAST_SECTION_NAME", &last_section_name)
        .replace("$STACKSIZE", &format!("{:#X}", stack_size))
        .replace("$FORCEACTIVE", &force_active.join("\n    "))
        .replace("$ARENAHI", &format!("{:#X}", obj.arena_hi.unwrap_or(0x81700000)));
    out = if auto_force_files {
        out.replace("$FORCEFILES", &force_files.join("\n    "))
    } else {
        out.replace("$FORCEFILES", "")
    };
    Ok(out)
}

pub fn obj_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("o")
}

pub fn asm_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("s")
}
