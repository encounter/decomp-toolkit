use std::{collections::BTreeSet, num::NonZeroU32};
use anyhow::{anyhow, bail, ensure, Context, Result};
use powerpc::{Extensions, Ins};

use crate::{
    analysis::cfa::SectionAddress,
    analysis::vm::JumpTableType,
    array_ref,
    obj::{
        ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbolKind, SectionIndex,
    },
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
    read_u32(section, address).map(|v| Ins::new(v, Extensions::xenon()))
}

pub fn read_u32(section: &ObjSection, address: u32) -> Option<u32> {
    let offset = (address as u64 - section.address) as usize;
    if section.data.len() < offset + 4 {
        return None;
    }
    Some(u32::from_be_bytes(*array_ref!(section.data, offset, 4)))
}

fn read_unresolved_relocation_address(
    obj: &ObjInfo,
    section: &ObjSection,
    address: u32,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    if let Some(reloc) = obj.unresolved_relocations.iter().find(|reloc| {
        reloc.section as SectionIndex == section.elf_index && reloc.address == address
    }) {
        if reloc.module_id != obj.module_id {
            return Ok(Some(RelocationTarget::External));
        }
        if let Some(reloc_kind) = reloc_kind {
            ensure!(reloc.kind == reloc_kind);
        }
        let (target_section_index, target_section) =
            obj.sections.get_elf_index(reloc.target_section as SectionIndex).ok_or_else(|| {
                anyhow!(
                    "Failed to find target section {} for unresolved relocation",
                    reloc.target_section
                )
            })?;
        Ok(Some(RelocationTarget::Address(SectionAddress {
            section: target_section_index,
            address: target_section.address as u32 + reloc.addend,
        })))
    } else {
        Ok(None)
    }
}

fn read_relocation_address(
    obj: &ObjInfo,
    section: &ObjSection,
    address: u32,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    let Some(reloc) = section.relocations.at(address) else {
        return Ok(None);
    };
    if let Some(reloc_kind) = reloc_kind {
        ensure!(reloc.kind == reloc_kind);
    }
    let symbol = &obj.symbols[reloc.target_symbol];
    let Some(section_index) = symbol.section else {
        return Ok(Some(RelocationTarget::External));
    };
    Ok(Some(RelocationTarget::Address(SectionAddress {
        section: section_index,
        address: (symbol.address as i64 + reloc.addend) as u32,
    })))
}

pub fn read_address(obj: &ObjInfo, section: &ObjSection, address: u32) -> Result<SectionAddress> {
    if obj.kind == ObjKind::Relocatable {
        let mut opt = read_relocation_address(obj, section, address, Some(ObjRelocKind::Absolute))?;
        if opt.is_none() {
            opt = read_unresolved_relocation_address(
                obj,
                section,
                address,
                Some(ObjRelocKind::Absolute),
            )?;
        }
        opt.and_then(|t| match t {
            RelocationTarget::Address(addr) => Some(addr),
            RelocationTarget::External => None,
        })
        .with_context(|| {
            format!("Failed to find relocation for {:#010X} in section {}", address, section.name)
        })
    } else {
        let offset = (address as u64 - section.address) as usize;
        let address = u32::from_be_bytes(*array_ref!(section.data, offset, 4));
        let (section_index, _) = obj.sections.at_address(address)?;
        Ok(SectionAddress::new(section_index, address))
    }
}

fn is_valid_jump_table_addr(obj: &ObjInfo, addr: SectionAddress, jump_table_type: JumpTableType) -> bool {
    match jump_table_type {
        // if absolute, jump table is in .text, in the middle of the func actually
        JumpTableType::Absolute => {
            let kind = obj.sections[addr.section].kind;
            kind == ObjSectionKind::Code && kind != ObjSectionKind::Bss
        },
        // else, addr must not be in code or bss
        JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) | JumpTableType::RelativeShorts(_) => {
            !matches!(obj.sections[addr.section].kind, ObjSectionKind::Code | ObjSectionKind::Bss)
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationTarget {
    Address(SectionAddress),
    External,
}

#[inline(never)]
pub fn relocation_target_for(
    obj: &ObjInfo,
    addr: SectionAddress,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    let section = &obj.sections[addr.section];
    let mut opt = read_relocation_address(obj, section, addr.address, reloc_kind)?;
    if opt.is_none() {
        opt = read_unresolved_relocation_address(obj, section, addr.address, reloc_kind)?;
    }
    Ok(opt)
}

fn get_jump_table_entries(
    obj: &ObjInfo,
    addr: SectionAddress, // the address the jump table is at
    jump_table_type: JumpTableType,
    size: Option<NonZeroU32>,
    from: SectionAddress, // the address of the bctr that uses the jump table
    function_start: SectionAddress,
    function_end: Option<SectionAddress>,
) -> Result<(Vec<SectionAddress>, u32)> {
    let section = &obj.sections[addr.section];
    // Check for an existing symbol with a known size, and use that if available.
    // Allows overriding jump table size analysis.
    let known_size = obj
        .symbols
        .kind_at_section_address(addr.section, addr.address, ObjSymbolKind::Object)
        .ok()
        .flatten()
        .and_then(|(_, s)| if s.size_known { NonZeroU32::new(s.size as u32) } else { None });

    if let Some(size) = known_size.or(size).map(|n| n.get()) {
        let num_entries = match jump_table_type {
            JumpTableType::Absolute => size / 4,
            JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => size,
            JumpTableType::RelativeShorts(_) => size / 2,
        };
        log::debug!(
            "Located jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            num_entries,
            from
        );
        let mut entries = Vec::with_capacity(num_entries as usize);
        let mut data = section.data_range(addr.address, addr.address + size)?;
        let relative_addr = match jump_table_type {
            JumpTableType::Absolute => None,
            JumpTableType::RelativeBytes(addr) |
            JumpTableType::RelativeBytesTimes4(addr) |
            JumpTableType::RelativeShorts(addr) => {
                match addr.context("No relative address to apply jump table offsets to!")? {
                    RelocationTarget::Address(addr) => Some(addr),
                    _ => bail!("No relative address to apply jump table offsets to! (RelocationTarget is type External)"),
                }
            },
        };
        let mut cur_addr = addr; // cur_addr == the address of the current jump table entry we're analyzing
        let increment = match jump_table_type {
            JumpTableType::Absolute => 4,
            JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => 1,
            JumpTableType::RelativeShorts(_) => 2,
        };
        loop {
            if data.is_empty() { break; }
            let reloc_address = match jump_table_type {
                JumpTableType::Absolute => cur_addr,
                JumpTableType::RelativeBytes(_) => { relative_addr.unwrap() + data[0] as u32 },
                JumpTableType::RelativeBytesTimes4(_) => { relative_addr.unwrap() + (data[0] as u32 * 4) },
                JumpTableType::RelativeShorts(_) => { relative_addr.unwrap() + u16::from_be_bytes(*array_ref!(data, 0, 2)) as u32 },
            };
            if let Some(target) =
                relocation_target_for(obj, reloc_address, Some(ObjRelocKind::Absolute))?
            {
                match target {
                    RelocationTarget::Address(addr) => entries.push(addr),
                    RelocationTarget::External => {
                        bail!("Jump table entry at {:#010X} points to external symbol", cur_addr)
                    }
                }
            } else {
                let entry_addr = match jump_table_type {
                    JumpTableType::Absolute => u32::from_be_bytes(*array_ref!(data, 0, 4)),
                    JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) | JumpTableType::RelativeShorts(_) => reloc_address.address,
                };
                if entry_addr > 0 {
                    let (section_index, _) =
                        obj.sections.at_address(entry_addr).with_context(|| {
                            format!(
                                "Invalid jump table entry {entry_addr:#010X} at {cur_addr:#010X}"
                            )
                        })?;
                    entries.push(SectionAddress::new(section_index, entry_addr));
                }
            }
            data = &data[increment..];
            cur_addr += increment as u32;
        }
        Ok((entries, size))
    } else {
        let mut entries = Vec::new();
        let mut cur_addr = addr;
        loop {
            let target = if let Some(target) =
                relocation_target_for(obj, cur_addr, Some(ObjRelocKind::Absolute))?
            {
                match target {
                    RelocationTarget::Address(addr) => addr,
                    RelocationTarget::External => break,
                }
            } else if obj.kind == ObjKind::Executable {
                let Some(value) = read_u32(section, cur_addr.address) else {
                    break;
                };
                let Ok((section_index, _)) = obj.sections.at_address(value) else {
                    break;
                };
                SectionAddress::new(section_index, value)
            } else {
                break;
            };
            if target < function_start || matches!(function_end, Some(end) if target >= end) {
                break;
            }
            entries.push(target);
            cur_addr += 4;
        }
        let size = cur_addr.address - addr.address;
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
    addr: SectionAddress, // the address the jump table is at
    jump_table_type: JumpTableType,
    size: Option<NonZeroU32>,
    from: SectionAddress, // the address of the bctr that uses the jump table
    function_start: SectionAddress,
    function_end: Option<SectionAddress>,
) -> Result<(BTreeSet<SectionAddress>, u32)> {
    if !is_valid_jump_table_addr(obj, addr, jump_table_type) {
        return Ok((BTreeSet::new(), 0));
    }
    let (entries, size) =
        get_jump_table_entries(obj, addr, jump_table_type, size, from, function_start, function_end).with_context(
            || format!("While fetching jump table entries starting at {addr:#010X}"),
        )?;
    Ok((BTreeSet::from_iter(entries.iter().cloned()), size))
}

pub fn skip_alignment(
    section: &ObjSection,
    mut addr: SectionAddress,
    end: SectionAddress,
) -> Option<SectionAddress> {
    let mut data = match section.data_range(addr.address, end.address) {
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
