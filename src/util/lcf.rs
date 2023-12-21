use std::path::PathBuf;

use anyhow::{bail, Result};
use itertools::Itertools;
use path_slash::PathBufExt;

use crate::{
    obj::{ObjInfo, ObjKind},
    util::align_up,
};

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

    // Guess section alignment
    let mut alignments = Vec::with_capacity(obj.sections.count());
    let mut last_section_end = origin as u32;
    for (_, section) in obj.sections.iter() {
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
        .map(|((_, s), align)| format!("{} ALIGN({:#X}):{{}}", s.name, align))
        .join("\n        ");

    let mut force_files = Vec::with_capacity(obj.link_order.len());
    for unit in &obj.link_order {
        let obj_path = obj_path_for_unit(&unit.name);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let mut force_active = force_active.to_vec();
    for symbol in obj.symbols.iter() {
        if symbol.flags.is_force_active() && symbol.flags.is_global() && !symbol.flags.is_no_write()
        {
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
    let mut force_files = Vec::with_capacity(obj.link_order.len());
    for unit in &obj.link_order {
        let obj_path = obj_path_for_unit(&unit.name);
        force_files.push(obj_path.file_name().unwrap().to_str().unwrap().to_string());
    }

    let mut force_active = force_active.to_vec();
    for symbol in obj.symbols.iter() {
        if symbol.flags.is_force_active() && symbol.flags.is_global() && !symbol.flags.is_no_write()
        {
            force_active.push(symbol.name.clone());
        }
    }

    let out = template
        .unwrap_or(LCF_PARTIAL_TEMPLATE)
        .replace("$FORCEACTIVE", &force_active.join("\n    "));
    Ok(out)
}

pub fn obj_path_for_unit(unit: &str) -> PathBuf { PathBuf::from_slash(unit).with_extension("o") }

pub fn asm_path_for_unit(unit: &str) -> PathBuf { PathBuf::from_slash(unit).with_extension("s") }
