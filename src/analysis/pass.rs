use anyhow::{bail, ensure, Result};
use flagset::FlagSet;
use itertools::Itertools;
use memchr::memmem;

use crate::{
    analysis::cfa::{AnalyzerState, FunctionInfo, SectionAddress},
    obj::{
        ObjInfo, ObjKind, ObjRelocKind, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, SectionIndex,
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
        for (&start, _) in
            state.functions.iter().filter(|(_, info)| info.analyzed && info.end.is_none())
        {
            let section = &obj.sections[start.section];
            let data = match section.data_range(start.address, 0) {
                Ok(ret) => ret,
                Err(_) => continue,
            };
            let trk_table_bytes = TRK_TABLE_HEADER.as_bytes();
            if data.starts_with(trk_table_bytes) && data[trk_table_bytes.len()] == 0 {
                log::debug!("Found gTRKInterruptVectorTable @ {:#010X}", start);
                state.known_symbols.entry(start).or_default().push(ObjSymbol {
                    name: "gTRKInterruptVectorTable".to_string(),
                    address: start.address as u64,
                    section: Some(start.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    ..Default::default()
                });
                let end = start + TRK_TABLE_SIZE;
                state.known_symbols.entry(end).or_default().push(ObjSymbol {
                    name: "gTRKInterruptVectorTableEnd".to_string(),
                    address: end.address as u64,
                    section: Some(start.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    ..Default::default()
                });

                return Ok(());
            }
        }
        log::debug!("gTRKInterruptVectorTable not found");
        Ok(())
    }
}

pub struct FindSaveRestSleds {}

#[allow(clippy::type_complexity)]
const SLEDS: [([u8; 8], &str, &str, u32, u32, u32); 6] = [
    ([0xd9, 0xcb, 0xff, 0x70, 0xd9, 0xeb, 0xff, 0x78], "__save_fpr", "_savefpr_", 14, 32, 4),
    ([0xc9, 0xcb, 0xff, 0x70, 0xc9, 0xeb, 0xff, 0x78], "__restore_fpr", "_restfpr_", 14, 32, 4),
    ([0x91, 0xcb, 0xff, 0xb8, 0x91, 0xeb, 0xff, 0xbc], "__save_gpr", "_savegpr_", 14, 32, 4),
    ([0x81, 0xcb, 0xff, 0xb8, 0x81, 0xeb, 0xff, 0xbc], "__restore_gpr", "_restgpr_", 14, 32, 4),
    ([0x39, 0x80, 0xff, 0x40, 0x7e, 0x8c, 0x01, 0xce], "_savevr", "_savev", 20, 32, 8),
    ([0x39, 0x80, 0xff, 0x40, 0x7e, 0x8c, 0x00, 0xce], "_restorevr", "_restv", 20, 32, 8),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSleds {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            for (needle, func, label, reg_start, reg_end, step_size) in SLEDS {
                let Some(pos) = memmem::find(&section.data, &needle) else {
                    continue;
                };
                let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);
                log::debug!("Found {} @ {:#010X}", func, start);
                let sled_size = (reg_end - reg_start) * step_size + 4 /* blr */;
                state.functions.insert(start, FunctionInfo {
                    analyzed: false,
                    end: Some(start + sled_size),
                    slices: None,
                });
                state.known_symbols.entry(start).or_default().push(ObjSymbol {
                    name: func.to_string(),
                    address: start.address as u64,
                    section: Some(start.section),
                    size: sled_size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                });
                for i in reg_start..reg_end {
                    let addr = start + (i - reg_start) * step_size;
                    state.known_symbols.entry(addr).or_default().push(ObjSymbol {
                        name: format!("{label}{i}"),
                        address: addr.address as u64,
                        section: Some(start.section),
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(())
    }
}

pub struct FindSaveRestSledsXbox {}

#[allow(clippy::type_complexity)]
const SLEDS_XBOX: [([u8; 8], &str, &str, u32, u32, u32); 8] = [
    ([0xf9, 0xc1, 0xff, 0x68, 0xf9, 0xe1, 0xff, 0x70], "__savegprlr", "__savegprlr_", 14, 32, 4),
    ([0xe9, 0xc1, 0xff, 0x68, 0xe9, 0xe1, 0xff, 0x70], "__restgprlr", "__restgprlr_", 14, 32, 4),
    ([0xd9, 0xcc, 0xff, 0x70, 0xd9, 0xec, 0xff, 0x78], "__savefpr", "__savefpr_", 14, 32, 4),
    ([0xc9, 0xcc, 0xff, 0x70, 0xc9, 0xec, 0xff, 0x78], "__restfpr", "__restfpr_", 14, 32, 4),
    ([0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce], "__savevmx", "__savevmx_", 14, 32, 8),
    ([0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb], "__savevmx_upper", "__savevmx_", 64, 128, 8),
    ([0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce], "__restvmx", "__restvmx_", 14, 32, 8),
    ([0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb], "__restvmx_upper", "__restvmx_", 64, 128, 8),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSledsXbox {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            for (needle, func, label, reg_start, reg_end, step_size) in SLEDS_XBOX {
                let Some(pos) = memmem::find(&section.data, &needle) else {
                    continue;
                };
                let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);
                log::debug!("Found {} @ {:#010X}", func, start);
                // let mut sled_size = (reg_end - reg_start) * step_size + 4 /* blr */;

                // save/restore gpr/fpr/vmx should've been found in pdata
                if !func.contains("_upper") {
                    assert!(obj.known_functions.contains_key(&start),
                        "Could not find reg intrinsic from pdata. Is that even possible for an xex?");
                }
                // add known symbols for them
                if obj.known_functions.contains_key(&start) {
                    let known_func_size = obj.known_functions.get(&start).unwrap().unwrap();
                    state.known_symbols.entry(start).or_default().push(ObjSymbol {
                        name: func.to_string(),
                        address: start.address as u64,
                        section: Some(start.section),
                        size: known_func_size as u64,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        kind: ObjSymbolKind::Function,
                        ..Default::default()
                    });
                }
                for i in reg_start..reg_end {
                    let addr = start + (i - reg_start) * step_size;
                    state.known_symbols.entry(addr).or_default().push(ObjSymbol {
                        name: format!("{label}{i}"),
                        address: addr.address as u64,
                        section: Some(start.section),
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(())
    }
}

pub struct FindRelCtorsDtors {}

impl AnalysisPass for FindRelCtorsDtors {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        ensure!(obj.kind == ObjKind::Relocatable);
        // ensure!(!obj.unresolved_relocations.is_empty());

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
                        && reloc.section as SectionIndex == section.elf_index
                        && reloc.address == current_address
                        && reloc.kind == ObjRelocKind::Absolute
                }) {
                    let Some((target_section_index, target_section)) =
                        obj.sections.iter().find(|(_, section)| {
                            section.elf_index == reloc.target_section as SectionIndex
                        })
                    else {
                        return false;
                    };
                    if target_section.kind != ObjSectionKind::Code
                        || !state
                            .functions
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
            log::debug!("Failed to find .ctors and .dtors");
            return Ok(());
        }

        log::debug!(
            "Found .ctors and .dtors: {}, {}",
            possible_sections[0].0,
            possible_sections[1].0
        );
        let ctors_section_index = possible_sections[0].0;
        let ctors_address = SectionAddress::new(ctors_section_index, 0);
        state.known_sections.insert(ctors_section_index, ".ctors".to_string());
        state.known_symbols.entry(ctors_address).or_default().push(ObjSymbol {
            name: "_ctors".to_string(),
            section: Some(ctors_section_index),
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        });

        let dtors_section_index = possible_sections[1].0;
        let dtors_address = SectionAddress::new(dtors_section_index, 0);
        state.known_sections.insert(dtors_section_index, ".dtors".to_string());
        state.known_symbols.entry(dtors_address).or_default().push(ObjSymbol {
            name: "_dtors".to_string(),
            section: Some(dtors_section_index),
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
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
            log::debug!("Failed to find .rodata and .data");
            return Ok(());
        }

        log::debug!(
            "Found .rodata and .data: {}, {}",
            possible_sections[0].0,
            possible_sections[1].0
        );
        let rodata_section_index = possible_sections[0].0;
        state.known_sections.insert(rodata_section_index, ".rodata".to_string());

        let data_section_index = possible_sections[1].0;
        state.known_sections.insert(data_section_index, ".data".to_string());

        Ok(())
    }
}
