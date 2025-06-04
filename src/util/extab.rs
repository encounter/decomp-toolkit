use anyhow::{Context, Result};
use itertools::Itertools;

use crate::obj::ObjInfo;

pub fn clean_extab(obj: &mut ObjInfo, mut padding: impl Iterator<Item = u8>) -> Result<usize> {
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
            // Check if the current action has padding
            if let Some(padding_offset) = action.get_struct_padding_offset() {
                let index = padding_offset as usize;
                let section_offset = (symbol.address - extab_section.address) as usize
                    + action.action_offset as usize;
                let mut clean_data: Vec<u8> = action.get_exaction_bytes(false);
                // Write the two padding bytes
                clean_data[index] = padding.next().unwrap_or(0);
                clean_data[index + 1] = padding.next().unwrap_or(0);

                let orig_data =
                    &mut extab_section.data[section_offset..section_offset + clean_data.len()];
                orig_data.copy_from_slice(&clean_data);
                updated = true;
            }
        }
        if updated {
            tracing::debug!(
                "Replaced uninitialized bytes in {} (extab {:#010X}..{:#010X})",
                symbol.name,
                symbol.address,
                symbol.address + symbol.size
            );
            num_cleaned += 1;
        }
    }
    Ok(num_cleaned)
}
