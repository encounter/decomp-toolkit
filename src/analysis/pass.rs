use std::ops::Range;

use anyhow::Result;
use flagset::FlagSet;

use crate::{
    analysis::cfa::AnalyzerState,
    obj::{ObjInfo, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
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
        for (&start, _) in state.function_bounds.iter().filter(|&(_, &end)| end == 0) {
            let (section, data) = match obj.section_data(start, 0) {
                Ok((section, data)) => (section, data),
                Err(_) => continue,
            };
            if data.starts_with(TRK_TABLE_HEADER.as_bytes())
                && data[TRK_TABLE_HEADER.as_bytes().len()] == 0
            {
                log::info!("Found gTRKInterruptVectorTable @ {:#010X}", start);
                state.known_symbols.insert(start, ObjSymbol {
                    name: "gTRKInterruptVectorTable".to_string(),
                    demangled_name: None,
                    address: start as u64,
                    section: Some(section.index),
                    size: 0,
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    kind: ObjSymbolKind::Unknown,
                });
                let end = start + TRK_TABLE_SIZE;
                state.known_symbols.insert(end, ObjSymbol {
                    name: "gTRKInterruptVectorTableEnd".to_string(),
                    demangled_name: None,
                    address: end as u64,
                    section: Some(section.index),
                    size: 0,
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    kind: ObjSymbolKind::Unknown,
                });

                return Ok(());
            }
        }
        log::info!("gTRKInterruptVectorTable not found");
        Ok(())
    }
}

pub struct FindSaveRestSleds {}

const SLEDS: [([u8; 4], &'static str, &'static str); 4] = [
    ([0xd9, 0xcb, 0xff, 0x70], "__save_fpr", "_savefpr_"),
    ([0xc9, 0xcb, 0xff, 0x70], "__restore_fpr", "_restfpr_"),
    ([0x91, 0xcb, 0xff, 0xb8], "__save_gpr", "_savegpr_"),
    ([0x81, 0xcb, 0xff, 0xb8], "__restore_gpr", "_restgpr_"),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSleds {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()> {
        const SLED_SIZE: usize = 19 * 4; // registers 14-31 + blr
        let mut clear_ranges: Vec<Range<u32>> = vec![];
        for (&start, _) in state.function_bounds.iter().filter(|&(_, &end)| end != 0) {
            let (section, data) = obj.section_data(start, 0)?;
            for (needle, func, label) in &SLEDS {
                if data.starts_with(needle) {
                    log::info!("Found {} @ {:#010X}", func, start);
                    clear_ranges.push(start + 4..start + SLED_SIZE as u32);
                    state.known_symbols.insert(start, ObjSymbol {
                        name: func.to_string(),
                        demangled_name: None,
                        address: start as u64,
                        section: Some(section.index),
                        size: SLED_SIZE as u64,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        kind: ObjSymbolKind::Function,
                    });
                    for i in 14..=31 {
                        let addr = start + (i - 14) * 4;
                        state.known_symbols.insert(addr, ObjSymbol {
                            name: format!("{}{}", label, i),
                            demangled_name: None,
                            address: addr as u64,
                            section: Some(section.index),
                            size: 0,
                            size_known: true,
                            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                            kind: ObjSymbolKind::Unknown,
                        });
                    }
                }
            }
        }
        for range in clear_ranges {
            for addr in range.step_by(4) {
                state.function_entries.remove(&addr);
                state.function_bounds.remove(&addr);
                state.function_slices.remove(&addr);
            }
        }
        Ok(())
    }
}
