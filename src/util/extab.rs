use anyhow::{Context, Result};
use itertools::Itertools;

use crate::obj::ObjInfo;

pub fn clean_extab(obj: &mut ObjInfo) -> Result<usize> {
    let (extab_section_index, extab_section) = obj
        .sections
        .iter_mut()
        .find(|(_, s)| s.name == "extab")
        .ok_or_else(|| anyhow::anyhow!("No extab section found"))?;
    let mut num_cleaned = 0;
    for (_symbol_index, symbol) in obj
        .symbols
        .for_section(extab_section_index)
        .filter(|(_, s)| s.size > 0)
        .sorted_by_key(|(_, s)| s.address)
    {
        let data = extab_section.symbol_data(symbol)?;
        let decoded = cwextab::decode_extab(data).with_context(|| {
            format!(
                "Failed to decode {} (extab {:#010X}..{:#010X})",
                symbol.name,
                symbol.address,
                symbol.address + symbol.size
            )
        })?;
        let mut updated = false;
        for action in &decoded.exception_actions {
            let section_offset =
                (symbol.address - extab_section.address) as usize + action.action_offset as usize;
            let clean_data = action.get_exaction_bytes(true);
            let orig_data =
                &mut extab_section.data[section_offset..section_offset + clean_data.len()];
            if orig_data != clean_data {
                updated = true;
                orig_data.copy_from_slice(&clean_data);
            }
        }
        if updated {
            tracing::debug!(
                "Removed uninitialized bytes in {} (extab {:#010X}..{:#010X})",
                symbol.name,
                symbol.address,
                symbol.address + symbol.size
            );
            num_cleaned += 1;
        }
    }
    Ok(num_cleaned)
}
