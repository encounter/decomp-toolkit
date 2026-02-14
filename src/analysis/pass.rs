use anyhow::Result;
use memchr::memmem;

use crate::{
    analysis::cfa::{AnalyzerState, SectionAddress},
    obj::{ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
};

pub trait AnalysisPass {
    fn execute(state: &mut AnalyzerState, obj: &ObjInfo) -> Result<()>;
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
