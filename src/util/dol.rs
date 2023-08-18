use std::{collections::BTreeMap, path::Path};

use anyhow::{anyhow, bail, ensure, Result};
use dol::{Dol, DolSection, DolSectionType};

use crate::{
    analysis::cfa::locate_sda_bases,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind,
    },
    util::file::{map_file, map_reader},
};

const MAX_TEXT_SECTIONS: usize = 7;
const MAX_DATA_SECTIONS: usize = 11;
const MAX_ROM_COPY_INFO_SIZE: usize = (MAX_TEXT_SECTIONS + MAX_DATA_SECTIONS + 1) * 3 * 4; // num sections * 3 entries * u32
const MAX_BSS_INIT_INFO_SIZE: usize = (MAX_DATA_SECTIONS + 1) * 2 * 4; // num sections * 2 entries * u32
const ETI_INIT_INFO_SIZE: usize = 16; // eti_start, eti_end, code_start, code_size

fn read_u32(dol: &Dol, addr: u32) -> Result<u32> {
    Ok(u32::from_be_bytes(dol.virtual_data_at(addr, 4)?.try_into()?))
}

pub fn process_dol<P: AsRef<Path>>(path: P) -> Result<ObjInfo> {
    let name = path
        .as_ref()
        .file_name()
        .and_then(|filename| filename.to_str())
        .unwrap_or_default()
        .to_string();
    let dol = {
        let mmap = map_file(path)?;
        Dol::read_from(map_reader(&mmap))?
    };

    // Locate _rom_copy_info
    let first_rom_section = dol
        .header
        .sections
        .iter()
        .find(|section| section.kind != DolSectionType::Bss)
        .ok_or_else(|| anyhow!("Failed to locate first rom section"))?;
    let init_section = section_by_address(&dol, dol.header.entry_point)
        .ok_or_else(|| anyhow!("Failed to locate .init section"))?;
    let rom_copy_info_addr = {
        let mut addr = init_section.target + init_section.size
            - MAX_ROM_COPY_INFO_SIZE as u32
            - MAX_BSS_INIT_INFO_SIZE as u32;
        loop {
            let value = read_u32(&dol, addr)?;
            if value == first_rom_section.target {
                log::debug!("Found _rom_copy_info @ {addr:#010X}");
                break Some(addr);
            }
            addr += 4;
            if addr >= init_section.target + init_section.size {
                log::warn!("Failed to locate _rom_copy_info");
                break None;
            }
        }
    };

    // Process _rom_copy_info
    let mut rom_sections = BTreeMap::<u32, u32>::new();
    let rom_copy_info_end = match rom_copy_info_addr {
        Some(mut addr) => loop {
            let rom = read_u32(&dol, addr)?;
            let copy = read_u32(&dol, addr + 4)?;
            ensure!(
                rom == copy,
                "Unsupported section: ROM address {rom:#010X} != copy address {copy:#010X}",
            );
            let size = read_u32(&dol, addr + 8)?;
            addr += 12;
            if size == 0 {
                log::debug!("Found _rom_copy_info end @ {addr:#010X}");
                break Some(addr);
            }
            if addr >= init_section.target + init_section.size {
                log::warn!("Failed to locate _rom_copy_info end");
                break None;
            }
            rom_sections.insert(rom, size);
        },
        None => None,
    };

    // Locate _bss_init_info
    let bss_section = dol
        .header
        .sections
        .iter()
        .find(|section| section.kind == DolSectionType::Bss)
        .ok_or_else(|| anyhow!("Failed to locate BSS section"))?;
    let bss_init_info_addr = match rom_copy_info_end {
        Some(mut addr) => loop {
            let value = read_u32(&dol, addr)?;
            if value == bss_section.target {
                log::debug!("Found _bss_init_info @ {addr:#010X}");
                break Some(addr);
            }
            addr += 4;
            if addr >= init_section.target + init_section.size {
                log::warn!("Failed to locate _bss_init_info");
                break None;
            }
        },
        None => None,
    };

    // Process _bss_init_info
    let mut bss_sections = BTreeMap::<u32, u32>::new();
    let bss_init_info_end = match bss_init_info_addr {
        Some(mut addr) => loop {
            let rom = read_u32(&dol, addr)?;
            let size = read_u32(&dol, addr + 4)?;
            addr += 8;
            if size == 0 {
                log::debug!("Found _bss_init_info end @ {addr:#010X}");
                break Some(addr);
            }
            if addr >= init_section.target + init_section.size {
                log::warn!("Failed to locate _bss_init_info end");
                break None;
            }
            bss_sections.insert(rom, size);
        },
        None => None,
    };

    // Locate _eti_init_info
    let num_text_sections =
        dol.header.sections.iter().filter(|section| section.kind == DolSectionType::Text).count();
    let mut eti_entries: Vec<EtiEntry> = Vec::new();
    let mut eti_init_info_range: Option<(u32, u32)> = None;
    let mut extab_section: Option<usize> = None;
    let mut extabindex_section: Option<usize> = None;
    'outer: for dol_section in
        dol.header.sections.iter().filter(|section| section.kind == DolSectionType::Data)
    {
        // Use section size from _rom_copy_info
        let dol_section_size = match rom_sections.get(&dol_section.target) {
            Some(&size) => size,
            None => dol_section.size,
        };
        let dol_section_end = dol_section.target + dol_section_size;

        let eti_init_info_addr = {
            let mut addr = dol_section_end - (ETI_INIT_INFO_SIZE * (num_text_sections + 1)) as u32;
            loop {
                let eti_init_info = read_eti_init_info(&dol, addr)?;
                if validate_eti_init_info(
                    &dol,
                    &eti_init_info,
                    dol_section,
                    dol_section_end,
                    &rom_sections,
                )? {
                    log::debug!("Found _eti_init_info @ {addr:#010X}");
                    break addr;
                }
                addr += 4;
                if addr > dol_section_end - ETI_INIT_INFO_SIZE as u32 {
                    continue 'outer;
                }
            }
        };

        let eti_init_info_end = {
            let mut addr = eti_init_info_addr;
            loop {
                let eti_init_info = read_eti_init_info(&dol, addr)?;
                addr += 16;
                if eti_init_info.is_zero() {
                    break;
                }
                if addr > dol_section_end - ETI_INIT_INFO_SIZE as u32 {
                    bail!(
                        "Failed to locate _eti_init_info end (start @ {:#010X})",
                        eti_init_info_addr
                    );
                }
                if !validate_eti_init_info(
                    &dol,
                    &eti_init_info,
                    dol_section,
                    dol_section_end,
                    &rom_sections,
                )? {
                    bail!("Invalid _eti_init_info entry: {:#010X?}", eti_init_info);
                }
                for addr in (eti_init_info.eti_start..eti_init_info.eti_end).step_by(12) {
                    let eti_entry = read_eti_entry(&dol, addr)?;
                    let entry_section =
                        section_by_address(&dol, eti_entry.extab_addr).ok_or_else(|| {
                            anyhow!(
                                "Failed to locate section for extab address {:#010X}",
                                eti_entry.extab_addr
                            )
                        })?;
                    if let Some(extab_section) = extab_section {
                        ensure!(
                            entry_section.index == extab_section,
                            "Mismatched sections for extabindex entries: {} != {}",
                            entry_section.index,
                            extab_section
                        );
                    } else {
                        extab_section = Some(entry_section.index);
                    }
                    eti_entries.push(eti_entry);
                }
            }
            log::debug!("Found _eti_init_info end @ {addr:#010X}");
            addr
        };

        eti_init_info_range = Some((eti_init_info_addr, eti_init_info_end));
        extabindex_section = Some(dol_section.index);
        break;
    }
    if eti_init_info_range.is_none() {
        log::debug!("Failed to locate _eti_init_info");
    }

    // Add text and data sections
    let mut sections = vec![];
    for dol_section in
        dol.header.sections.iter().filter(|section| section.kind != DolSectionType::Bss)
    {
        let (name, kind, known) = match dol_section.index {
            idx if idx == init_section.index => (".init".to_string(), ObjSectionKind::Code, true),
            idx if Some(idx) == extab_section => {
                ("extab".to_string(), ObjSectionKind::ReadOnlyData, true)
            }
            idx if Some(idx) == extabindex_section => {
                ("extabindex".to_string(), ObjSectionKind::ReadOnlyData, true)
            }
            _ if num_text_sections == 2 && dol_section.kind == DolSectionType::Text => {
                (".text".to_string(), ObjSectionKind::Code, true)
            }
            idx => match dol_section.kind {
                DolSectionType::Text => (format!(".text{idx}"), ObjSectionKind::Code, false),
                DolSectionType::Data => (format!(".data{idx}"), ObjSectionKind::Data, false),
                DolSectionType::Bss => unreachable!(),
            },
        };

        // Use section size from _rom_copy_info
        let size = match rom_sections.get(&dol_section.target) {
            Some(&size) => size,
            None => {
                if !rom_sections.is_empty() {
                    log::warn!(
                        "Section {} ({:#010X}) doesn't exist in _rom_copy_info",
                        dol_section.index,
                        dol_section.target
                    );
                }
                dol_section.size
            }
        };

        sections.push(ObjSection {
            name,
            kind,
            address: dol_section.target as u64,
            size: size as u64,
            data: dol.virtual_data_at(dol_section.target, size)?.to_vec(),
            align: 0,
            elf_index: 0,
            relocations: vec![],
            original_address: 0,
            file_offset: dol_section.offset as u64,
            section_known: known,
            splits: Default::default(),
        });
    }

    // Add BSS sections from _bss_init_info
    for (idx, (&addr, &size)) in bss_sections.iter().enumerate() {
        ensure!(
            addr >= bss_section.target
                && addr < bss_section.target + bss_section.size
                && addr + size <= bss_section.target + bss_section.size,
            "Invalid BSS range {:#010X}-{:#010X} (DOL BSS: {:#010X}-{:#010X})",
            addr,
            addr + size,
            bss_section.target,
            bss_section.target + bss_section.size
        );

        sections.push(ObjSection {
            name: format!(".bss{}", idx),
            kind: ObjSectionKind::Bss,
            address: addr as u64,
            size: size as u64,
            data: vec![],
            align: 0,
            elf_index: 0,
            relocations: vec![],
            original_address: 0,
            file_offset: 0,
            section_known: false,
            splits: Default::default(),
        });
    }

    // Sort sections by address ascending
    sections.sort_by_key(|s| s.address);

    // Apply section indices
    let mut init_section_index = None;
    for (idx, section) in sections.iter_mut().enumerate() {
        match section.name.as_str() {
            ".init" => {
                init_section_index = Some(idx);
            }
            "extab" => {
                extab_section = Some(idx);
            }
            "extabindex" => {
                extabindex_section = Some(idx);
            }
            _ => {}
        }
        // Assume the original ELF section index is +1
        // ELF files start with a NULL section
        section.elf_index = idx + 1;
    }

    // Create object
    let mut obj =
        ObjInfo::new(ObjKind::Executable, ObjArchitecture::PowerPc, name, vec![], sections);
    obj.entry = dol.header.entry_point as u64;

    // Generate _rom_copy_info symbol
    if let (Some(rom_copy_info_addr), Some(rom_copy_info_end)) =
        (rom_copy_info_addr, rom_copy_info_end)
    {
        obj.add_symbol(
            ObjSymbol {
                name: "_rom_copy_info".to_string(),
                demangled_name: None,
                address: rom_copy_info_addr as u64,
                section: init_section_index,
                size: (rom_copy_info_end - rom_copy_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                align: None,
                data_kind: Default::default(),
            },
            true,
        )?;
    }

    // Generate _bss_init_info symbol
    if let (Some(bss_init_info_addr), Some(bss_init_info_end)) =
        (bss_init_info_addr, bss_init_info_end)
    {
        obj.add_symbol(
            ObjSymbol {
                name: "_bss_init_info".to_string(),
                demangled_name: None,
                address: bss_init_info_addr as u64,
                section: init_section_index,
                size: (bss_init_info_end - bss_init_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                align: None,
                data_kind: Default::default(),
            },
            true,
        )?;
    }

    // Generate _eti_init_info symbol
    if let Some((eti_init_info_addr, eti_init_info_end)) = eti_init_info_range {
        obj.add_symbol(
            ObjSymbol {
                name: "_eti_init_info".to_string(),
                demangled_name: None,
                address: eti_init_info_addr as u64,
                section: extabindex_section,
                size: (eti_init_info_end - eti_init_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                align: None,
                data_kind: Default::default(),
            },
            true,
        )?;
    }

    // Generate symbols for extab & extabindex entries
    if let (Some(extabindex_section_index), Some(extab_section_index)) =
        (extabindex_section, extab_section)
    {
        let extab_section = &obj.sections[extab_section_index];
        let extab_section_address = extab_section.address;
        let extab_section_size = extab_section.size;

        for entry in &eti_entries {
            // Add functions from extabindex entries as known function bounds
            if let Some(old_value) = obj.known_functions.insert(entry.function, entry.function_size)
            {
                if old_value != entry.function_size {
                    log::warn!(
                        "Conflicting sizes for {:#010X}: {:#X} != {:#X}",
                        entry.function,
                        entry.function_size,
                        old_value
                    );
                }
            }
            obj.add_symbol(
                ObjSymbol {
                    name: format!("@eti_{:08X}", entry.address),
                    demangled_name: None,
                    address: entry.address as u64,
                    section: Some(extabindex_section_index),
                    size: 12,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local | ObjSymbolFlags::Hidden),
                    kind: ObjSymbolKind::Object,
                    align: None,
                    data_kind: Default::default(),
                },
                false,
            )?;
        }

        let mut entry_iter = eti_entries.iter().peekable();
        loop {
            let (addr, size) = match (entry_iter.next(), entry_iter.peek()) {
                (Some(a), Some(&b)) => (a.extab_addr, b.extab_addr - a.extab_addr),
                (Some(a), None) => (
                    a.extab_addr,
                    (extab_section_address + extab_section_size) as u32 - a.extab_addr,
                ),
                _ => break,
            };
            obj.add_symbol(
                ObjSymbol {
                    name: format!("@etb_{:08X}", addr),
                    demangled_name: None,
                    address: addr as u64,
                    section: Some(extab_section_index),
                    size: size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local | ObjSymbolFlags::Hidden),
                    kind: ObjSymbolKind::Object,
                    align: None,
                    data_kind: Default::default(),
                },
                false,
            )?;
        }
    }

    // Locate _SDA2_BASE_ & _SDA_BASE_
    match locate_sda_bases(&mut obj) {
        Ok(true) => {
            let sda2_base = obj.sda2_base.unwrap();
            let sda_base = obj.sda_base.unwrap();
            obj.add_symbol(
                ObjSymbol {
                    name: "_SDA2_BASE_".to_string(),
                    demangled_name: None,
                    address: sda2_base as u64,
                    section: None,
                    size: 0,
                    size_known: false,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Unknown,
                    align: None,
                    data_kind: Default::default(),
                },
                true,
            )?;
            obj.add_symbol(
                ObjSymbol {
                    name: "_SDA_BASE_".to_string(),
                    demangled_name: None,
                    address: sda_base as u64,
                    section: None,
                    size: 0,
                    size_known: false,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Unknown,
                    align: None,
                    data_kind: Default::default(),
                },
                true,
            )?;
        }
        Ok(false) => {
            log::warn!("Unable to locate SDA bases");
        }
        Err(e) => {
            log::warn!("Failed to locate SDA bases: {:?}", e);
        }
    }

    Ok(obj)
}

#[derive(Debug, Clone)]
struct EtiInitInfo {
    eti_start: u32,
    eti_end: u32,
    code_start: u32,
    code_size: u32,
}

impl EtiInitInfo {
    #[inline]
    fn is_zero(&self) -> bool {
        self.eti_start == 0 && self.eti_end == 0 && self.code_start == 0 && self.code_size == 0
    }
}

#[derive(Debug, Clone)]
struct EtiEntry {
    address: u32,
    function: u32,
    function_size: u32,
    extab_addr: u32,
}

fn read_eti_init_info(dol: &Dol, addr: u32) -> Result<EtiInitInfo> {
    let eti_start = read_u32(dol, addr)?;
    let eti_end = read_u32(dol, addr + 4)?;
    let code_start = read_u32(dol, addr + 8)?;
    let code_size = read_u32(dol, addr + 12)?;
    Ok(EtiInitInfo { eti_start, eti_end, code_start, code_size })
}

fn read_eti_entry(dol: &Dol, address: u32) -> Result<EtiEntry> {
    let function = read_u32(dol, address)?;
    let function_size = read_u32(dol, address + 4)?;
    let extab_addr = read_u32(dol, address + 8)?;
    Ok(EtiEntry { address, function, function_size, extab_addr })
}

fn validate_eti_init_info(
    dol: &Dol,
    eti_init_info: &EtiInitInfo,
    eti_section: &DolSection,
    eti_section_end: u32,
    rom_sections: &BTreeMap<u32, u32>,
) -> Result<bool> {
    if eti_init_info.eti_start >= eti_section.target
        && eti_init_info.eti_start < eti_section_end
        && eti_init_info.eti_end >= eti_section.target
        && eti_init_info.eti_end < eti_section_end
    {
        if let Some(code_section) = section_by_address(dol, eti_init_info.code_start) {
            let code_section_size = match rom_sections.get(&code_section.target) {
                Some(&size) => size,
                None => code_section.size,
            };
            if eti_init_info.code_size <= code_section_size {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn section_by_address(dol: &Dol, addr: u32) -> Option<&DolSection> {
    dol.header
        .sections
        .iter()
        .find(|section| addr >= section.target && addr < section.target + section.size)
}
