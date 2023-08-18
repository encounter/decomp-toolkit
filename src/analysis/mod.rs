use std::{collections::BTreeSet, num::NonZeroU32};

use anyhow::{Context, Result};
use ppc750cl::Ins;

use crate::{
    array_ref,
    obj::{ObjInfo, ObjSection, ObjSectionKind},
};

pub mod cfa;
pub mod executor;
pub mod objects;
pub mod pass;
pub mod signatures;
pub mod slices;
pub mod tracker;
pub mod vm;

pub fn disassemble(section: &ObjSection, address: u32) -> Option<Ins> {
    read_u32(&section.data, address, section.address as u32).map(|code| Ins::new(code, address))
}

pub fn read_u32(data: &[u8], address: u32, section_address: u32) -> Option<u32> {
    let offset = (address - section_address) as usize;
    if data.len() < offset + 4 {
        return None;
    }
    Some(u32::from_be_bytes(*array_ref!(data, offset, 4)))
}

fn is_valid_jump_table_addr(obj: &ObjInfo, addr: u32) -> bool {
    matches!(obj.sections.at_address(addr), Ok((_, section)) if section.kind != ObjSectionKind::Bss)
}

fn get_jump_table_entries(
    obj: &ObjInfo,
    addr: u32,
    size: Option<NonZeroU32>,
    from: u32,
    function_start: u32,
    function_end: u32,
) -> Result<(Vec<u32>, u32)> {
    let (_, section) = obj.sections.at_address(addr).with_context(|| {
        format!("Failed to get jump table entries @ {:#010X} size {:?}", addr, size)
    })?;
    let offset = (addr as u64 - section.address) as usize;
    if let Some(size) = size.map(|n| n.get()) {
        log::trace!(
            "Located jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            size / 4,
            from
        );
        let jt_data = &section.data[offset..offset + size as usize];
        let entries =
            jt_data.chunks_exact(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect();
        Ok((entries, size))
    } else {
        let mut entries = Vec::new();
        let mut cur_addr = addr;
        while let Some(value) = read_u32(&section.data, cur_addr, section.address as u32) {
            if value < function_start || value >= function_end {
                break;
            }
            entries.push(value);
            cur_addr += 4;
        }
        let size = cur_addr - addr;
        log::debug!(
            "Guessed jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            size / 4,
            from
        );
        Ok((entries, size))
    }
}

pub fn uniq_jump_table_entries(
    obj: &ObjInfo,
    addr: u32,
    size: Option<NonZeroU32>,
    from: u32,
    function_start: u32,
    function_end: u32,
) -> Result<(BTreeSet<u32>, u32)> {
    if !is_valid_jump_table_addr(obj, addr) {
        return Ok((BTreeSet::new(), 0));
    }
    let (entries, size) =
        get_jump_table_entries(obj, addr, size, from, function_start, function_end)?;
    Ok((BTreeSet::from_iter(entries.iter().cloned().filter(|&addr| addr != 0)), size))
}

pub fn skip_alignment(section: &ObjSection, mut addr: u32, end: u32) -> Option<u32> {
    let mut data = match section.data_range(addr, end) {
        Ok(data) => data,
        Err(_) => return None,
    };
    loop {
        if data.is_empty() {
            break None;
        }
        if data[0..4] == [0u8; 4] {
            addr += 4;
            data = &data[4..];
        } else {
            break Some(addr);
        }
    }
}
