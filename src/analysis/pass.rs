use std::ops::Range;

use anyhow::{bail, ensure, Result};
use flagset::FlagSet;
use itertools::Itertools;

use crate::{
    analysis::cfa::{AnalyzerState, SectionAddress},
    obj::{
        ObjInfo, ObjKind, ObjRelocKind, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind,
    },
};

pub trait AnalysisPass {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()>;
}

pub struct FindTRKInterruptVectorTable {}

pub const TRK_TABLE_HEADER: &str = "Metrowerks Target Resident Kernel for PowerPC";
pub const TRK_TABLE_SIZE: u32 = 0x1F34; // always?

// TRK_MINNOW_DOLPHIN.a __exception.s
impl AnalysisPass for FindTRKInterruptVectorTable {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        for (&start, _) in state.function_bounds.iter().filter(|&(_, &end)| end.is_none()) {
            let section = &obj.sections[start.section];
            let data = match section.data_range(start.address, 0) {
                Ok(ret) => ret,
                Err(_) => continue,
            };
            if data.starts_with(TRK_TABLE_HEADER.as_bytes())
                && data[TRK_TABLE_HEADER.as_bytes().len()] == 0
            {
                log::info!("Found gTRKInterruptVectorTable @ {:#010X}", start);
                state.known_symbols.insert(start, ObjSymbol {
                    name: "gTRKInterruptVectorTable".to_string(),
                    demangled_name: None,
                    address: start.address as u64,
                    section: Some(start.section),
                    size: 0,
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    kind: ObjSymbolKind::Unknown,
                    align: None,
                    data_kind: Default::default(),
                });
                let end = start + TRK_TABLE_SIZE;
                state.known_symbols.insert(end, ObjSymbol {
                    name: "gTRKInterruptVectorTableEnd".to_string(),
                    demangled_name: None,
                    address: end.address as u64,
                    section: Some(start.section),
                    size: 0,
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    kind: ObjSymbolKind::Unknown,
                    align: None,
                    data_kind: Default::default(),
                });

                return Ok(());
            }
        }
        log::debug!("gTRKInterruptVectorTable not found");
        Ok(())
    }
}

pub struct FindSaveRestSleds {}

const SLEDS: [([u8; 4], &str, &str); 4] = [
    ([0xd9, 0xcb, 0xff, 0x70], "__save_fpr", "_savefpr_"),
    ([0xc9, 0xcb, 0xff, 0x70], "__restore_fpr", "_restfpr_"),
    ([0x91, 0xcb, 0xff, 0xb8], "__save_gpr", "_savegpr_"),
    ([0x81, 0xcb, 0xff, 0xb8], "__restore_gpr", "_restgpr_"),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSleds {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        const SLED_SIZE: usize = 19 * 4; // registers 14-31 + blr
        let mut clear_ranges: Vec<Range<SectionAddress>> = vec![];
        for (&start, _) in state.function_bounds.iter().filter(|&(_, &end)| end.is_some()) {
            let section = &obj.sections[start.section];
            let data = match section.data_range(start.address, 0) {
                Ok(ret) => ret,
                Err(_) => continue,
            };
            for (needle, func, label) in &SLEDS {
                if data.starts_with(needle) {
                    log::debug!("Found {} @ {:#010X}", func, start);
                    clear_ranges.push(start + 4..start + SLED_SIZE as u32);
                    state.known_symbols.insert(start, ObjSymbol {
                        name: func.to_string(),
                        demangled_name: None,
                        address: start.address as u64,
                        section: Some(start.section),
                        size: SLED_SIZE as u64,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        kind: ObjSymbolKind::Function,
                        align: None,
                        data_kind: Default::default(),
                    });
                    for i in 14..=31 {
                        let addr = start + (i - 14) * 4;
                        state.known_symbols.insert(addr, ObjSymbol {
                            name: format!("{}{}", label, i),
                            demangled_name: None,
                            address: addr.address as u64,
                            section: Some(start.section),
                            size: 0,
                            size_known: true,
                            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                            kind: ObjSymbolKind::Unknown,
                            align: None,
                            data_kind: Default::default(),
                        });
                    }
                }
            }
        }
        for range in clear_ranges {
            let mut addr = range.start;
            while addr < range.end {
                state.function_entries.remove(&addr);
                state.function_bounds.remove(&addr);
                state.function_slices.remove(&addr);
                addr += 4;
            }
        }
        Ok(())
    }
}

pub struct FindRelCtorsDtors {}

impl AnalysisPass for FindRelCtorsDtors {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        ensure!(obj.kind == ObjKind::Relocatable);
        ensure!(!obj.unresolved_relocations.is_empty());

        match (obj.sections.by_name(".ctors")?, obj.sections.by_name(".dtors")?) {
            (Some(_), Some(_)) => return Ok(()),
            (None, None) => {}
            _ => bail!("Only one of .ctors and .dtors has been found?"),
        }

        let possible_sections = obj
            .sections
            .iter()
            .filter(|&(index, section)| {
                if section.section_known
                    || state.known_sections.contains_key(&index)
                    || !matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
                    || section.size < 4
                {
                    return false;
                }

                let mut current_address = section.address as u32;
                let section_end = current_address + section.size as u32;
                // Check that each word has a relocation to a function
                // And the section ends with a null pointer
                while let Some(reloc) = obj.unresolved_relocations.iter().find(|reloc| {
                    reloc.module_id == obj.module_id
                        && reloc.section == section.elf_index as u8
                        && reloc.address == current_address
                        && reloc.kind == ObjRelocKind::Absolute
                }) {
                    let Some((target_section_index, target_section)) = obj
                        .sections
                        .iter()
                        .find(|(_, section)| section.elf_index == reloc.target_section as usize)
                    else {
                        return false;
                    };
                    if target_section.kind != ObjSectionKind::Code
                        || !state
                            .function_bounds
                            .contains_key(&SectionAddress::new(target_section_index, reloc.addend))
                    {
                        return false;
                    }
                    current_address += 4;
                    if current_address >= section_end {
                        return false;
                    }
                }
                if current_address + 4 != section_end {
                    return false;
                }
                section.data_range(section_end - 4, section_end).ok() == Some(&[0; 4])
            })
            .collect_vec();

        if possible_sections.len() != 2 {
            log::warn!("Failed to find .ctors and .dtors");
            return Ok(());
        }

        log::debug!("Found .ctors and .dtors: {:?}", possible_sections);
        let ctors_section_index = possible_sections[0].0;
        state.known_sections.insert(ctors_section_index, ".ctors".to_string());
        state.known_symbols.insert(SectionAddress::new(ctors_section_index, 0), ObjSymbol {
            name: "_ctors".to_string(),
            demangled_name: None,
            address: 0,
            section: Some(ctors_section_index),
            size: 0,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: Default::default(),
            align: None,
            data_kind: Default::default(),
        });

        let dtors_section_index = possible_sections[1].0;
        state.known_sections.insert(dtors_section_index, ".dtors".to_string());
        state.known_symbols.insert(SectionAddress::new(dtors_section_index, 0), ObjSymbol {
            name: "_dtors".to_string(),
            demangled_name: None,
            address: 0,
            section: Some(dtors_section_index),
            size: 0,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: Default::default(),
            align: None,
            data_kind: Default::default(),
        });

        // Check for duplicate entries in .dtors, indicating __destroy_global_chain_reference
        // let mut dtors_entries = vec![];
        // let mut current_address = obj.sections[dtors_section_index].address as u32;
        // let section_end = current_address + obj.sections[dtors_section_index].size as u32;
        // while let Some(reloc) = obj.unresolved_relocations.iter().find(|reloc| {
        //     reloc.module_id == obj.module_id
        //         && reloc.section == obj.sections[dtors_section_index].elf_index as u8
        //         && reloc.address == current_address
        //         && reloc.kind == ObjRelocKind::Absolute
        // }) {
        //     let Some((target_section_index, target_section)) = obj
        //         .sections
        //         .iter()
        //         .find(|(_, section)| section.elf_index == reloc.target_section as usize)
        //     else {
        //         bail!("Failed to find target section for .dtors entry");
        //     };
        //     if target_section.kind != ObjSectionKind::Code
        //         || !state
        //             .function_bounds
        //             .contains_key(&SectionAddress::new(target_section_index, reloc.addend))
        //     {
        //         bail!("Failed to find target function for .dtors entry");
        //     }
        //     dtors_entries.push(SectionAddress::new(target_section_index, reloc.addend));
        //     current_address += 4;
        //     if current_address >= section_end {
        //         bail!("Failed to find null terminator for .dtors");
        //     }
        // }
        // if current_address + 4 != section_end {
        //     bail!("Failed to find null terminator for .dtors");
        // }
        // if dtors_entries.len() != dtors_entries.iter().unique().count() {
        //     log::debug!("Found __destroy_global_chain_reference");
        //     state.known_symbols.insert(SectionAddress::new(dtors_section_index, 0), ObjSymbol {
        //         name: "__destroy_global_chain_reference".to_string(),
        //         demangled_name: None,
        //         address: 0,
        //         section: Some(dtors_section_index),
        //         size: 4,
        //         size_known: true,
        //         flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
        //         kind: ObjSymbolKind::Object,
        //         align: None,
        //         data_kind: Default::default(),
        //     });
        // }

        Ok(())
    }
}

pub struct FindRelRodataData {}

impl AnalysisPass for FindRelRodataData {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        ensure!(obj.kind == ObjKind::Relocatable);

        match (obj.sections.by_name(".rodata")?, obj.sections.by_name(".data")?) {
            (None, None) => {}
            _ => return Ok(()),
        }

        let possible_sections = obj
            .sections
            .iter()
            .filter(|&(index, section)| {
                !section.section_known
                    && !state.known_sections.contains_key(&index)
                    && matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
            })
            .collect_vec();

        if possible_sections.len() != 2 {
            log::warn!("Failed to find .rodata and .data");
            return Ok(());
        }

        log::debug!("Found .rodata and .data: {:?}", possible_sections);
        let rodata_section_index = possible_sections[0].0;
        state.known_sections.insert(rodata_section_index, ".rodata".to_string());

        let data_section_index = possible_sections[1].0;
        state.known_sections.insert(data_section_index, ".data".to_string());

        Ok(())
    }
}
