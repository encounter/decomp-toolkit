use std::path::PathBuf;

use anyhow::Result;
use itertools::Itertools;

use crate::obj::ObjInfo;

pub fn generate_ldscript(obj: &ObjInfo) -> Result<String> {
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
        let obj_path = obj_path_for_unit(unit);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let out = include_str!("../../assets/ldscript.lcf")
        .replacen("$SECTIONS", &section_defs, 1)
        .replacen("$STACKSIZE", &format!("{:#X}", stack_size), 1)
        .replacen("$FORCEFILES", &force_files.join("\n    "), 1);
    Ok(out)
}

pub fn obj_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("o")
}

pub fn asm_path_for_unit(unit: &str) -> PathBuf {
    PathBuf::from(unit).with_extension("").with_extension("s")
}
