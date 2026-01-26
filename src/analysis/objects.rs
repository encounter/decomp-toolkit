use anyhow::Result;

use crate::{
    obj::{ObjDataKind, ObjInfo, ObjSectionKind, ObjSymbolKind, SymbolIndex},
    util::{config::is_auto_symbol, split::is_linker_generated_label},
};

pub fn detect_objects(obj: &mut ObjInfo) -> Result<()> {
    for (section_index, section) in
        obj.sections.iter_mut().filter(|(_, s)| s.kind != ObjSectionKind::Code)
    {
        let section_end = (section.address + section.size) as u32;

        let mut replace_symbols = vec![];
        for (idx, symbol) in obj.symbols.for_section(section_index) {
            let mut symbol = symbol.clone();
            if is_linker_generated_label(&symbol.name) || symbol.name.starts_with("..") {
                continue;
            }
            let expected_size = match symbol.data_kind {
                ObjDataKind::Byte => 1,
                ObjDataKind::Byte2 | ObjDataKind::Short => 2,
                ObjDataKind::Byte4 | ObjDataKind::Float | ObjDataKind::Int => 4,
                ObjDataKind::Byte8 | ObjDataKind::Double => 8,
                _ => {
                    if symbol.name.contains("NULL_THUNK_DATA") {
                        4
                    } else {
                        0
                    }
                }
            };
            if !symbol.size_known {
                let next_addr = obj
                    .symbols
                    .for_section_range(section_index, symbol.address as u32 + 1..)
                    .next()
                    .map_or(section_end, |(_, symbol)| symbol.address as u32);
                let new_size = next_addr - symbol.address as u32;
                log::debug!("Guessed {} size {:#X}", symbol.name, new_size);
                symbol.size = match (new_size, expected_size) {
                    (..=4, 1) => expected_size,
                    (2 | 4, 2) => expected_size,
                    (..=8, 1 | 2 | 4) => {
                        // alignment to double
                        if obj.symbols.at_section_address(section_index, next_addr).any(|(_, sym)| sym.data_kind == ObjDataKind::Double)
                        // If we're at a TU boundary, we can assume it's just padding
                        || section.splits.has_split_at(symbol.address as u32 + new_size)
                        {
                            expected_size
                        } else {
                            new_size
                        }
                    }
                    _ => {
                        if symbol.name.contains("NULL_THUNK_DATA") {
                            4
                        } else {
                            new_size
                        }
                    }
                } as u64;
                symbol.size_known = true;
            }
            symbol.kind = ObjSymbolKind::Object;
            if expected_size > 1 && symbol.size as u32 % expected_size != 0 {
                symbol.data_kind = ObjDataKind::Unknown;
            }
            replace_symbols.push((idx, symbol));
        }
        for (idx, symbol) in replace_symbols {
            obj.symbols.replace(idx, symbol)?;
        }
    }
    Ok(())
}

pub fn detect_strings(obj: &mut ObjInfo) -> Result<()> {
    let mut symbols_set = Vec::<(SymbolIndex, ObjDataKind, usize)>::new();
    for (section_index, section) in obj
        .sections
        .iter()
        .filter(|(_, s)| matches!(s.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData))
    {
        enum StringResult {
            None,
            String { length: usize, terminated: bool },
            WString { length: usize, str: String },
        }
        pub const fn trim_zeroes_end(mut bytes: &[u8]) -> &[u8] {
            while let [rest @ .., last] = bytes {
                if *last == 0 {
                    bytes = rest;
                } else {
                    break;
                }
            }
            bytes
        }
        fn is_string(data: &[u8]) -> StringResult {
            let bytes = trim_zeroes_end(data);
            if bytes.is_empty() {
                return StringResult::None;
            }
            if bytes.iter().all(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                return StringResult::String {
                    length: bytes.len(),
                    terminated: data.len() > bytes.len(),
                };
            }
            if bytes.len() % 2 == 0 && data.len() >= bytes.len() + 2 {
                // Found at least 2 bytes of trailing 0s, check UTF-16
                let mut ok = true;
                let mut str = String::new();
                for n in std::char::decode_utf16(
                    bytes.chunks_exact(2).map(|c| u16::from_be_bytes(c.try_into().unwrap())),
                ) {
                    match n {
                        Ok(c) if c.is_ascii_graphic() || c.is_ascii_whitespace() => {
                            str.push(c);
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    return StringResult::WString { length: bytes.len(), str };
                }
            }
            StringResult::None
        }
        for (symbol_idx, symbol) in obj
            .symbols
            .for_section(section_index)
            .filter(|(_, sym)| sym.data_kind == ObjDataKind::Unknown)
        {
            if symbol.name.starts_with("@stringBase") {
                symbols_set.push((symbol_idx, ObjDataKind::StringTable, symbol.size as usize));
                continue;
            }

            let data = section.symbol_data(symbol)?;
            match is_string(data) {
                StringResult::None => {}
                StringResult::String { length, terminated } => {
                    let size = if terminated { length + 1 } else { length };
                    if symbol.size == size as u64
                        || (is_auto_symbol(symbol) && symbol.size > size as u64)
                    {
                        let str = String::from_utf8_lossy(&data[..length]);
                        log::debug!("Found string '{}' @ {}", str, symbol.name);
                        symbols_set.push((symbol_idx, ObjDataKind::String, size));
                    }
                }
                StringResult::WString { length, str } => {
                    let size = length + 2;
                    if symbol.size == size as u64
                        || (is_auto_symbol(symbol) && symbol.size > size as u64)
                    {
                        log::debug!("Found wide string '{}' @ {}", str, symbol.name);
                        symbols_set.push((symbol_idx, ObjDataKind::String16, size));
                    }
                }
            }
        }
    }

    for (symbol_idx, data_kind, size) in symbols_set {
        let mut symbol = obj.symbols[symbol_idx].clone();
        log::debug!("Setting {} ({:#010X}) to size {:#X}", symbol.name, symbol.address, size);
        symbol.data_kind = data_kind;
        symbol.size = size as u64;
        symbol.size_known = true;
        obj.symbols.replace(symbol_idx, symbol)?;
    }
    Ok(())
}
