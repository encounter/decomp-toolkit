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
            let section_offset = (symbol.address - extab_section.address) as usize
                + action.action_offset as usize
                + 2;
            // TODO: does cwextab provide a way to serialize the action back to bytes?
            let clean_data = match action.get_exaction_data() {
                cwextab::ExActionData::DestroyLocalCond {
                    condition,
                    pad4: _,
                    local_offset,
                    dtor_address,
                } => {
                    let mut clean_data = Vec::new();
                    clean_data.extend_from_slice(&condition.to_be_bytes());
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.extend_from_slice(&local_offset.to_be_bytes());
                    clean_data.extend_from_slice(&dtor_address.to_be_bytes());
                    Some(clean_data)
                }
                cwextab::ExActionData::DestroyMemberCond {
                    condition,
                    object_pointer,
                    member_offset,
                    pad8: _,
                    dtor_address,
                } => {
                    let mut clean_data = Vec::new();
                    clean_data.extend_from_slice(&condition.to_be_bytes());
                    clean_data.extend_from_slice(&object_pointer.to_be_bytes());
                    clean_data.extend_from_slice(&member_offset.to_be_bytes());
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.extend_from_slice(&dtor_address.to_be_bytes());
                    Some(clean_data)
                }
                cwextab::ExActionData::DeletePointerCond {
                    condition,
                    object_pointer,
                    pad4: _,
                    dtor_address,
                } => {
                    let mut clean_data = Vec::new();
                    clean_data.extend_from_slice(&condition.to_be_bytes());
                    clean_data.extend_from_slice(&object_pointer.to_be_bytes());
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.extend_from_slice(&dtor_address.to_be_bytes());
                    Some(clean_data)
                }
                cwextab::ExActionData::CatchBlock {
                    pad0: _,
                    catch_type,
                    catch_pc_offset,
                    cinfo_ref,
                } => {
                    let mut clean_data = Vec::new();
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.extend_from_slice(&catch_type.to_be_bytes());
                    clean_data.extend_from_slice(&catch_pc_offset.to_be_bytes());
                    clean_data.extend_from_slice(&cinfo_ref.to_be_bytes());
                    Some(clean_data)
                }
                cwextab::ExActionData::CatchBlock32 {
                    pad0: _,
                    catch_type,
                    catch_pc_offset,
                    cinfo_ref,
                } => {
                    let mut clean_data = Vec::new();
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.push(padding.next().unwrap_or(0));
                    clean_data.extend_from_slice(&catch_type.to_be_bytes());
                    clean_data.extend_from_slice(&catch_pc_offset.to_be_bytes());
                    clean_data.extend_from_slice(&cinfo_ref.to_be_bytes());
                    Some(clean_data)
                }
                cwextab::ExActionData::EndOfList
                | cwextab::ExActionData::Branch { .. }
                | cwextab::ExActionData::DestroyLocal { .. }
                | cwextab::ExActionData::DestroyLocalPointer { .. }
                | cwextab::ExActionData::DestroyLocalArray { .. }
                | cwextab::ExActionData::DestroyBase { .. }
                | cwextab::ExActionData::DestroyMember { .. }
                | cwextab::ExActionData::DestroyMemberArray { .. }
                | cwextab::ExActionData::DeletePointer { .. }
                | cwextab::ExActionData::ActiveCatchBlock { .. }
                | cwextab::ExActionData::Terminate
                | cwextab::ExActionData::Specification { .. } => None,
            };
            if let Some(clean_data) = clean_data {
                let orig_data =
                    &mut extab_section.data[section_offset..section_offset + clean_data.len()];
                orig_data.copy_from_slice(&clean_data);
                updated = true;
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
