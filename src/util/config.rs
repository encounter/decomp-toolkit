use std::{
    io::{BufRead, Write},
    iter,
    num::ParseIntError,
    str::FromStr,
};

use anyhow::{anyhow, bail, Result};
use cwdemangle::{demangle, DemangleOptions};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::obj::{ObjInfo, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind};
use crate::util::nested::NestedVec;

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
    static COMMENT_LINE: Lazy<Regex> = Lazy::new(|| Regex::new("^\\s*(?://|#).*$").unwrap());

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
    let _ = symbol;
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

pub fn write_splits<W: Write>(
    w: &mut W,
    obj: &ObjInfo,
    obj_files: Option<Vec<String>>,
) -> Result<()> {
    let mut obj_files_iter = obj_files.map(|v| v.into_iter());
    for unit in &obj.link_order {
        let obj_file = if let Some(obj_files_iter) = &mut obj_files_iter {
            obj_files_iter.next()
        } else {
            None
        };
        log::info!("Processing {} (obj file {:?})", unit, obj_file);
        if let Some(obj_file) = obj_file {
            let trim_unit = unit
                .trim_end_matches("_1")
                .trim_end_matches(" (asm)")
                .trim_end_matches(".o")
                .trim_end_matches(".cpp")
                .trim_end_matches(".c");
            if !obj_file.contains(trim_unit) {
                bail!("Unit mismatch: {} vs {}", unit, obj_file);
            }
            let trim_obj = obj_file
                .trim_end_matches(" \\")
                .trim_start_matches("\t$(BUILD_DIR)/")
                .trim_start_matches("asm/")
                .trim_start_matches("src/");
            writeln!(w, "{}:", trim_obj)?;
        } else {
            writeln!(w, "{}:", unit)?;
        }
        let mut split_iter = obj.splits.iter()
            .flat_map(|(addr, v)| v.iter().map(move |u| (addr, u))).peekable();
        while let Some((&addr, it_unit)) = split_iter.next() {
            if it_unit != unit {
                continue;
            }
            let end = split_iter.peek().map(|(&addr, _)| addr).unwrap_or(u32::MAX);
            let section = obj.section_at(addr)?;
            writeln!(w, "\t{:<11} start:{:#010X} end:{:#010X}", section.name, addr, end)?;
            // align:{}
        }
        writeln!(w)?;
    }
    Ok(())
}

enum SplitLine {
    Unit { name: String },
    Section { name: String, start: u32, end: u32, align: Option<u32> },
    None,
}

fn parse_split_line(line: &str) -> Result<SplitLine> {
    static UNIT_LINE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^\\s*(?P<name>[^\\s:]+)\\s*:\\s*$").unwrap());
    static SECTION_LINE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^\\s*(?P<name>\\S+)\\s*(?P<attrs>.*)$").unwrap());
    static COMMENT_LINE: Lazy<Regex> = Lazy::new(|| Regex::new("^\\s*(?://|#).*$").unwrap());

    if line.is_empty() || COMMENT_LINE.is_match(line) {
        Ok(SplitLine::None)
    } else if let Some(captures) = UNIT_LINE.captures(&line) {
        let name = captures["name"].to_string();
        Ok(SplitLine::Unit { name })
    } else if let Some(captures) = SECTION_LINE.captures(&line) {
        let mut name = captures["name"].to_string();
        let mut start: Option<u32> = None;
        let mut end: Option<u32> = None;
        let mut align: Option<u32> = None;

        let attrs = captures["attrs"].split(' ');
        for attr in attrs {
            if let Some((attr, value)) = attr.split_once(':') {
                match attr {
                    "start" => {
                        start = Some(parse_hex(&value)?);
                    }
                    "end" => {
                        end = Some(parse_hex(&value)?);
                    }
                    "align" => align = Some(u32::from_str(value)?),
                    "rename" => name = value.to_string(),
                    _ => bail!("Unknown attribute '{name}'"),
                }
            } else {
                bail!("Unknown attribute '{attr}'")
            }
        }
        if let (Some(start), Some(end)) = (start, end) {
            Ok(SplitLine::Section { name, start, end, align })
        } else {
            Err(anyhow!("Missing attribute: '{line}'"))
        }
    } else {
        Err(anyhow!("Failed to parse line: '{line}'"))
    }
}

pub fn apply_splits<R: BufRead>(r: R, obj: &mut ObjInfo) -> Result<()> {
    enum SplitState {
        None,
        Unit(String),
    }
    let mut state = SplitState::None;
    for result in r.lines() {
        let line = match result {
            Ok(line) => line,
            Err(e) => return Err(e.into()),
        };
        let split_line = parse_split_line(&line)?;
        match (&mut state, split_line) {
            (SplitState::None | SplitState::Unit(_), SplitLine::Unit { name }) => {
                obj.link_order.push(name.clone());
                state = SplitState::Unit(name);
            }
            (SplitState::None, SplitLine::Section { name, .. }) => {
                bail!("Section {} defined outside of unit", name);
            }
            (SplitState::Unit(unit), SplitLine::Section { name, start, end, align }) => {
                let _ = end;
                let _ = align;
                obj.splits.nested_push(start, unit.clone());
                obj.named_sections.insert(start, name);
            }
            _ => {}
        }
    }
    Ok(())
}
