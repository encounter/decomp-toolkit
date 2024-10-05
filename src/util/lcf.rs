use std::path::PathBuf;

use anyhow::Result;
use itertools::Itertools;
use path_slash::PathBufExt;

use crate::obj::{ObjInfo, ObjKind};

const LCF_TEMPLATE: &str = include_str!("../../assets/ldscript.lcf");
const LCF_PARTIAL_TEMPLATE: &str = include_str!("../../assets/ldscript_partial.lcf");

pub fn generate_ldscript(
    obj: &ObjInfo,
    template: Option<&str>,
    force_active: &[String],
) -> Result<String> {
    if obj.kind == ObjKind::Relocatable {
        return generate_ldscript_partial(obj, template, force_active);
    }

    let origin = obj.sections.iter().map(|(_, s)| s.address).min().unwrap();
    let stack_size = match (obj.stack_address, obj.stack_end) {
        (Some(stack_address), Some(stack_end)) => stack_address - stack_end,
        _ => 65535, // default
    };

    let section_defs = obj
        .sections
        .iter()
        .map(|(_, s)| format!("{} ALIGN({:#X}):{{}}", s.name, s.align))
        .join("\n        ");

    let mut force_files = Vec::with_capacity(obj.link_order.len());
    for unit in &obj.link_order {
        let obj_path = obj_path_for_unit(&unit.name);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let mut force_active = force_active.to_vec();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.flags.is_exported() && symbol.flags.is_global() && !symbol.flags.is_no_write() {
            force_active.push(symbol.name.clone());
        }
    }

    // Hack to handle missing .sbss2 section... what's the proper way?
    let last_section_name = obj.sections.iter().next_back().unwrap().1.name.clone();
    let last_section_symbol = format!("_f_{}", last_section_name.trim_start_matches('.'));

    let out = template
        .unwrap_or(LCF_TEMPLATE)
        .replace("$ORIGIN", &format!("{:#X}", origin))
        .replace("$SECTIONS", &section_defs)
        .replace("$LAST_SECTION_SYMBOL", &last_section_symbol)
        .replace("$LAST_SECTION_NAME", &last_section_name)
        .replace("$STACKSIZE", &format!("{:#X}", stack_size))
        .replace("$FORCEACTIVE", &force_active.join("\n    "))
        .replace("$ARENAHI", &format!("{:#X}", obj.arena_hi.unwrap_or(0x81700000)));
    Ok(out)
}

pub fn generate_ldscript_partial(
    obj: &ObjInfo,
    template: Option<&str>,
    force_active: &[String],
) -> Result<String> {
    let mut section_defs = obj
        .sections
        .iter()
        .map(|(_, s)| {
            let inner = if s.name == ".data" { " *(.data) *(extabindex) *(extab) " } else { "" };
            format!("{} ALIGN({:#X}):{{{}}}", s.name, s.align, inner)
        })
        .join("\n        ");

    // Some RELs have no entry point (`.text` was stripped) so mwld requires at least an empty
    // `.init` section to be present in the linker script, for some reason.
    if obj.entry.is_none() {
        section_defs = format!(".init :{{}}\n        {}", section_defs);
    }

    let mut force_files = Vec::with_capacity(obj.link_order.len());
    for unit in &obj.link_order {
        let obj_path = obj_path_for_unit(&unit.name);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let mut force_active = force_active.to_vec();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.flags.is_exported() && symbol.flags.is_global() && !symbol.flags.is_no_write() {
            force_active.push(symbol.name.clone());
        }
    }

    let out = template
        .unwrap_or(LCF_PARTIAL_TEMPLATE)
        .replace("$SECTIONS", &section_defs)
        .replace("$FORCEACTIVE", &force_active.join("\n    "));
    Ok(out)
}

pub fn obj_path_for_unit(unit: &str) -> PathBuf { PathBuf::from_slash(unit).with_extension("o") }

pub fn asm_path_for_unit(unit: &str) -> PathBuf { PathBuf::from_slash(unit).with_extension("s") }
