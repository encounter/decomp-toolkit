use std::{
    io::{BufRead, Write},
    num::ParseIntError,
    path::Path,
    str::FromStr,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use cwdemangle::{demangle, DemangleOptions};
use once_cell::sync::Lazy;
use regex::{Captures, Regex};

use crate::{
    obj::{
        ObjDataKind, ObjInfo, ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
        ObjUnit,
    },
    util::{
        file::{buf_writer, map_file, map_reader},
        nested::NestedVec,
    },
};

fn parse_hex(s: &str) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16)
}

pub fn apply_symbols_file<P: AsRef<Path>>(path: P, obj: &mut ObjInfo) -> Result<bool> {
    Ok(if path.as_ref().is_file() {
        let map = map_file(path)?;
        for result in map_reader(&map).lines() {
            let line = match result {
                Ok(line) => line,
                Err(e) => bail!("Failed to process symbols file: {e:?}"),
            };
            if let Some(symbol) = parse_symbol_line(&line, obj)? {
                obj.add_symbol(symbol, true)?;
            }
        }
        true
    } else {
        false
    })
}

pub fn parse_symbol_line(line: &str, obj: &mut ObjInfo) -> Result<Option<ObjSymbol>> {
    static SYMBOL_LINE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            "^\\s*(?P<name>[^\\s=]+)\\s*=\\s*(?:(?P<section>[A-Za-z0-9.]+):)?(?P<addr>[0-9A-Fa-fXx]+);(?:\\s*//\\s*(?P<attrs>.*))?$",
        )
        .unwrap()
    });
    static COMMENT_LINE: Lazy<Regex> = Lazy::new(|| Regex::new("^\\s*(?://|#).*$").unwrap());

    if let Some(captures) = SYMBOL_LINE.captures(line) {
        let name = captures["name"].to_string();
        let addr = parse_hex(&captures["addr"])?;
        let section_name = captures["section"].to_string();
        let section = if let Some(section) = obj.sections.iter().find(|s| s.name == section_name) {
            Some(section.index)
        } else if let Some(section) = obj.sections.iter_mut().find(|s| s.contains(addr)) {
            if !section.section_known {
                section.rename(section_name)?;
            }
            Some(section.index)
        } else {
            None
        };
        let demangled_name = demangle(&name, &DemangleOptions::default());
        let mut symbol = ObjSymbol {
            name,
            demangled_name,
            address: addr as u64,
            section,
            size: 0,
            size_known: false,
            flags: Default::default(),
            kind: ObjSymbolKind::Unknown,
            align: None,
            data_kind: Default::default(),
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
                        symbol.size = parse_hex(value)? as u64;
                        symbol.size_known = true;
                    }
                    "scope" => {
                        symbol.flags.0 |= symbol_flags_from_str(value)
                            .ok_or_else(|| anyhow!("Unknown symbol scope '{}'", value))?;
                    }
                    "align" => {
                        symbol.align = Some(parse_hex(value)?);
                    }
                    "data" => {
                        symbol.data_kind = symbol_data_kind_from_str(value)
                            .ok_or_else(|| anyhow!("Unknown symbol data type '{}'", value))?;
                    }
                    _ => bail!("Unknown symbol attribute '{name}'"),
                }
            } else {
                match attr {
                    "hidden" => {
                        symbol.flags.0 |= ObjSymbolFlags::Hidden;
                    }
                    "force_active" => {
                        symbol.flags.0 |= ObjSymbolFlags::ForceActive;
                    }
                    "noreloc" => {
                        ensure!(
                            symbol.size != 0,
                            "Symbol {} requires size != 0 with noreloc",
                            symbol.name
                        );
                        obj.blocked_ranges.insert(addr, addr + symbol.size as u32);
                    }
                    _ => bail!("Unknown symbol attribute '{attr}'"),
                }
            }
        }
        Ok(Some(symbol))
    } else if line.is_empty() || COMMENT_LINE.is_match(line) {
        Ok(None)
    } else {
        Err(anyhow!("Failed to parse symbol line '{line}'"))
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

#[inline]
pub fn write_symbols_file<P: AsRef<Path>>(path: P, obj: &ObjInfo) -> Result<()> {
    let mut w = buf_writer(path)?;
    write_symbols(&mut w, obj)?;
    w.flush()?;
    Ok(())
}

pub fn write_symbols<W: Write>(w: &mut W, obj: &ObjInfo) -> Result<()> {
    for (_, symbol) in obj.symbols.iter_ordered() {
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
    if let Some(align) = symbol.align {
        write!(w, " align:{align:#X}")?;
    }
    if let Some(kind) = symbol_data_kind_to_str(symbol.data_kind) {
        write!(w, " data:{kind}")?;
    }
    if symbol.flags.is_hidden() {
        write!(w, " hidden")?;
    }
    if symbol.flags.is_force_active() {
        write!(w, " force_active")?;
    }
    if obj.blocked_ranges.contains_key(&(symbol.address as u32)) {
        write!(w, " noreloc")?;
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
fn symbol_data_kind_to_str(kind: ObjDataKind) -> Option<&'static str> {
    match kind {
        ObjDataKind::Unknown => None,
        ObjDataKind::Byte => Some("byte"),
        ObjDataKind::Byte2 => Some("2byte"),
        ObjDataKind::Byte4 => Some("4byte"),
        ObjDataKind::Byte8 => Some("8byte"),
        ObjDataKind::Float => Some("float"),
        ObjDataKind::Double => Some("double"),
        ObjDataKind::String => Some("string"),
        ObjDataKind::String16 => Some("wstring"),
        ObjDataKind::StringTable => Some("string_table"),
        ObjDataKind::String16Table => Some("wstring_table"),
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
    if flags.0.contains(ObjSymbolFlags::Weak) {
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

#[inline]
fn symbol_data_kind_from_str(s: &str) -> Option<ObjDataKind> {
    match s {
        "byte" => Some(ObjDataKind::Byte),
        "2byte" => Some(ObjDataKind::Byte2),
        "4byte" => Some(ObjDataKind::Byte4),
        "8byte" => Some(ObjDataKind::Byte8),
        "float" => Some(ObjDataKind::Float),
        "double" => Some(ObjDataKind::Double),
        "string" => Some(ObjDataKind::String),
        "wstring" => Some(ObjDataKind::String16),
        "string_table" => Some(ObjDataKind::StringTable),
        "wstring_table" => Some(ObjDataKind::String16Table),
        _ => None,
    }
}

#[inline]
pub fn write_splits_file<P: AsRef<Path>>(path: P, obj: &ObjInfo) -> Result<()> {
    let mut w = buf_writer(path)?;
    write_splits(&mut w, obj)?;
    w.flush()?;
    Ok(())
}

pub fn write_splits<W: Write>(w: &mut W, obj: &ObjInfo) -> Result<()> {
    let mut begin = true;
    for unit in obj.link_order.iter().filter(|unit| !unit.autogenerated) {
        if begin {
            begin = false;
        } else {
            writeln!(w)?;
        }

        write!(w, "{}:", unit.name)?;
        if let Some(comment_version) = unit.comment_version {
            write!(w, " comment:{}", comment_version)?;
        }
        writeln!(w)?;
        let mut split_iter = obj.splits_for_range(..).peekable();
        while let Some((addr, split)) = split_iter.next() {
            if split.unit != unit.name {
                continue;
            }
            let end = if split.end > 0 {
                split.end
            } else {
                split_iter.peek().map(|&(addr, _)| addr).unwrap_or(0)
            };
            let section = obj.section_at(addr)?;
            write!(w, "\t{:<11} start:{:#010X} end:{:#010X}", section.name, addr, end)?;
            // if let Some(align) = split.align {
            //     write!(w, " align:{}", align)?;
            // }
            if split.common {
                write!(w, " common")?;
            }
            if let Some(name) = obj.named_sections.get(&addr) {
                if name != &section.name {
                    write!(w, " rename:{}", name)?;
                }
            }
            writeln!(w)?;
        }
    }
    Ok(())
}

struct SplitSection {
    name: String,
    start: u32,
    end: u32,
    align: Option<u32>,
    /// Whether this is a part of common BSS.
    common: bool,
}

struct SplitUnit {
    name: String,
    /// MW `.comment` section version
    comment_version: Option<u8>,
}

enum SplitLine {
    Unit(SplitUnit),
    Section(SplitSection),
    None,
}

fn parse_split_line(line: &str) -> Result<SplitLine> {
    static UNIT_LINE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^\\s*(?P<name>[^\\s:]+)\\s*:\\s*(?P<attrs>.*)$").unwrap());
    static SECTION_LINE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^\\s*(?P<name>\\S+)\\s*(?P<attrs>.*)$").unwrap());
    static COMMENT_LINE: Lazy<Regex> = Lazy::new(|| Regex::new("^\\s*(?://|#).*$").unwrap());

    if line.is_empty() || COMMENT_LINE.is_match(line) {
        Ok(SplitLine::None)
    } else if let Some(captures) = UNIT_LINE.captures(line) {
        parse_unit_line(captures).with_context(|| format!("While parsing split line: '{line}'"))
    } else if let Some(captures) = SECTION_LINE.captures(line) {
        parse_section_line(captures).with_context(|| format!("While parsing split line: '{line}'"))
    } else {
        Err(anyhow!("Failed to parse split line: '{line}'"))
    }
}

fn parse_unit_line(captures: Captures) -> Result<SplitLine> {
    let mut unit = SplitUnit { name: captures["name"].to_string(), comment_version: None };

    for attr in captures["attrs"].split(' ').filter(|&s| !s.is_empty()) {
        if let Some((attr, value)) = attr.split_once(':') {
            match attr {
                "comment" => unit.comment_version = Some(u8::from_str(value)?),
                _ => bail!("Unknown unit attribute '{}'", attr),
            }
        } else {
            bail!("Unknown unit attribute '{attr}'");
        }
    }

    Ok(SplitLine::Unit(unit))
}

fn parse_section_line(captures: Captures) -> Result<SplitLine> {
    let mut section = SplitSection {
        name: captures["name"].to_string(),
        start: 0,
        end: 0,
        align: None,
        common: false,
    };

    for attr in captures["attrs"].split(' ').filter(|&s| !s.is_empty()) {
        if let Some((attr, value)) = attr.split_once(':') {
            match attr {
                "start" => section.start = parse_hex(value)?,
                "end" => section.end = parse_hex(value)?,
                "align" => section.align = Some(u32::from_str(value)?),
                "rename" => section.name = value.to_string(),
                _ => bail!("Unknown split attribute '{attr}'"),
            }
        } else {
            match attr {
                "common" => {
                    section.common = true;
                    if section.align.is_none() {
                        section.align = Some(4);
                    }
                }
                _ => bail!("Unknown split attribute '{attr}'"),
            }
        }
    }
    if section.start > 0 && section.end > 0 {
        Ok(SplitLine::Section(section))
    } else {
        Err(anyhow!("Section '{}' missing start or end address", section.name))
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
            (
                SplitState::None | SplitState::Unit(_),
                SplitLine::Unit(SplitUnit { name, comment_version }),
            ) => {
                obj.link_order.push(ObjUnit {
                    name: name.clone(),
                    autogenerated: false,
                    comment_version,
                });
                state = SplitState::Unit(name);
            }
            (SplitState::None, SplitLine::Section(SplitSection { name, .. })) => {
                bail!("Section {} defined outside of unit", name);
            }
            (
                SplitState::Unit(unit),
                SplitLine::Section(SplitSection { name, start, end, align, common }),
            ) => {
                obj.splits.nested_push(start, ObjSplit {
                    unit: unit.clone(),
                    end,
                    align,
                    common,
                    autogenerated: false,
                });
                obj.named_sections.insert(start, name);
            }
            _ => {}
        }
    }
    Ok(())
}
