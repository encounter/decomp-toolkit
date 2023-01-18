use std::{io::Write, num::ParseIntError, ops::BitAndAssign};

use anyhow::{anyhow, bail, Result};
use cwdemangle::{demangle, DemangleOptions};
use flagset::FlagSet;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::util::obj::{
    ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
};

fn parse_hex(s: &str) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16)
}

pub fn parse_symbol_line(line: &str, obj: &ObjInfo) -> Result<Option<ObjSymbol>> {
    static SYMBOL_LINE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            "^\\s*(?P<name>[^\\s=]+)\\s*=\\s*(?:(?P<section>[A-Za-z0-9.]+):)?(?P<addr>[0-9A-Fa-fXx]+);(?:\\s*//\\s*(?P<attrs>.*))?$",
        )
        .unwrap()
    });
    static COMMENT_LINE: Lazy<Regex> = Lazy::new(|| Regex::new("^\\s*//.*$").unwrap());

    if let Some(captures) = SYMBOL_LINE.captures(&line) {
        let name = captures["name"].to_string();
        let addr = parse_hex(&captures["addr"])?;
        let demangled_name = demangle(&name, &DemangleOptions::default());
        let mut symbol = ObjSymbol {
            name,
            demangled_name,
            address: addr as u64,
            section: obj.section_at(addr).ok().map(|section| section.index),
            size: 0,
            size_known: false,
            flags: Default::default(),
            kind: ObjSymbolKind::Unknown,
        };
        let attrs = captures["attrs"].split(' ');
        for attr in attrs {
            if let Some((name, value)) = attr.split_once(':') {
                match name {
                    "type" => {
                        symbol.kind = symbol_kind_from_str(value)
                            .ok_or_else(|| anyhow!("Unknown symbol type '{}'", value))?;
                    }
                    "size" => {
                        symbol.size = parse_hex(&value)? as u64;
                        symbol.size_known = true;
                    }
                    "scope" => {
                        symbol.flags.0 |= symbol_flags_from_str(value)
                            .ok_or_else(|| anyhow!("Unknown symbol scope '{}'", value))?;
                    }
                    _ => bail!("Unknown attribute '{name}'"),
                }
            } else {
                match attr {
                    "hidden" => {
                        symbol.flags.0 |= ObjSymbolFlags::Hidden;
                    }
                    _ => bail!("Unknown attribute '{attr}'"),
                }
            }
        }
        Ok(Some(symbol))
    } else if COMMENT_LINE.is_match(line) {
        Ok(None)
    } else {
        Err(anyhow!("Failed to parse line '{line}'"))
    }
}

fn is_skip_symbol(symbol: &ObjSymbol) -> bool {
    // symbol.name.starts_with("lbl_")
    //     || symbol.name.starts_with("func_")
    //     || symbol.name.starts_with("switch_")
    //     || symbol.name.starts_with("float_")
    //     || symbol.name.starts_with("double_")
    false
}

pub fn write_symbols<W: Write>(w: &mut W, obj: &ObjInfo) -> Result<()> {
    let mut symbols: Vec<&ObjSymbol> = obj.symbols.iter().map(|s| s).collect();
    symbols.sort_by_key(|s| s.address);
    for symbol in symbols {
        if symbol.kind == ObjSymbolKind::Section
            // Ignore absolute symbols for now (usually linker-generated)
            || symbol.section.is_none()
            || is_skip_symbol(symbol)
        {
            continue;
        }
        write_symbol(w, obj, symbol)?;
    }
    Ok(())
}

fn write_symbol<W: Write>(w: &mut W, obj: &ObjInfo, symbol: &ObjSymbol) -> Result<()> {
    // if let Some(demangled_name) = &symbol.demangled_name {
    //     writeln!(w, "// {demangled_name}")?;
    // }
    write!(w, "{} = ", symbol.name)?;
    let section = symbol.section.and_then(|idx| obj.sections.get(idx));
    if let Some(section) = section {
        write!(w, "{}:", section.name)?;
    }
    write!(w, "{:#010X}; //", symbol.address)?;
    write!(w, " type:{}", symbol_kind_to_str(symbol.kind))?;
    // if let Some(section) = section {
    //     match section.kind {
    //         ObjSectionKind::Code => {
    //             write!(w, " type:function")?;
    //         }
    //         ObjSectionKind::Data | ObjSectionKind::ReadOnlyData | ObjSectionKind::Bss => {
    //             write!(w, " type:object")?;
    //         }
    //     }
    // }
    if symbol.size_known && symbol.size > 0 {
        write!(w, " size:{:#X}", symbol.size)?;
    }
    if let Some(scope) = symbol_flags_to_str(symbol.flags) {
        write!(w, " scope:{scope}")?;
    }
    if symbol.flags.0.contains(ObjSymbolFlags::Hidden) {
        write!(w, " hidden")?;
    }
    writeln!(w)?;
    Ok(())
}

#[inline]
fn symbol_kind_to_str(kind: ObjSymbolKind) -> &'static str {
    match kind {
        ObjSymbolKind::Unknown => "label",
        ObjSymbolKind::Function => "function",
        ObjSymbolKind::Object => "object",
        ObjSymbolKind::Section => "section",
    }
}

#[inline]
fn symbol_kind_from_str(s: &str) -> Option<ObjSymbolKind> {
    match s {
        "label" => Some(ObjSymbolKind::Unknown),
        "function" => Some(ObjSymbolKind::Function),
        "object" => Some(ObjSymbolKind::Object),
        "section" => Some(ObjSymbolKind::Section),
        _ => None,
    }
}

#[inline]
fn symbol_flags_to_str(flags: ObjSymbolFlagSet) -> Option<&'static str> {
    if flags.0.contains(ObjSymbolFlags::Common) {
        Some("common")
    } else if flags.0.contains(ObjSymbolFlags::Weak) {
        Some("weak")
    } else if flags.0.contains(ObjSymbolFlags::Global) {
        Some("global")
    } else if flags.0.contains(ObjSymbolFlags::Local) {
        Some("local")
    } else {
        None
    }
}

#[inline]
fn symbol_flags_from_str(s: &str) -> Option<ObjSymbolFlags> {
    match s {
        "common" => Some(ObjSymbolFlags::Common),
        "weak" => Some(ObjSymbolFlags::Weak),
        "global" => Some(ObjSymbolFlags::Global),
        "local" => Some(ObjSymbolFlags::Local),
        _ => None,
    }
}
