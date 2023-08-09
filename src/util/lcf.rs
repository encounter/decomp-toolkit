use std::path::PathBuf;

use anyhow::Result;
use itertools::Itertools;

use crate::obj::ObjInfo;

pub fn generate_ldscript(obj: &ObjInfo, auto_force_files: bool) -> Result<String> {
    let stack_size = match (obj.stack_address, obj.stack_end) {
        (Some(stack_address), Some(stack_end)) => stack_address - stack_end,
        _ => 65535, // default
    };

    let section_defs = obj
        .sections
        .iter()
        .map(|s| format!("{} ALIGN({:#X}):{{}}", s.name, 0x20 /* TODO */))
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
        .replacen("$SECTIONS", &section_defs, 1)
        .replace("$LAST_SECTION_SYMBOL", &last_section_symbol)
        .replace("$LAST_SECTION_NAME", &last_section_name)
        .replacen("$STACKSIZE", &format!("{:#X}", stack_size), 1)
        .replacen("$FORCEACTIVE", &force_active.join("\n    "), 1);
    out = if auto_force_files {
        out.replacen("$FORCEFILES", &force_files.join("\n    "), 1)
    } else {
        out.replacen("$FORCEFILES", "", 1)
    };
    Ok(out)
}

pub fn obj_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("o")
}

pub fn asm_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("s")
}
