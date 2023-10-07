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
    analysis::cfa::SectionAddress,
    obj::{
        ObjDataKind, ObjInfo, ObjKind, ObjSectionKind, ObjSplit, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, ObjUnit,
    },
    util::{
        file::{buf_writer, map_file},
        split::default_section_align,
    },
};

fn parse_hex(s: &str) -> Result<u32, ParseIntError> {
    if s.starts_with("0x") {
        u32::from_str_radix(s.trim_start_matches("0x"), 16)
    } else {
        s.parse::<u32>()
    }
}

pub fn apply_symbols_file<P: AsRef<Path>>(path: P, obj: &mut ObjInfo) -> Result<bool> {
    Ok(if path.as_ref().is_file() {
        let file = map_file(path)?;
        for result in file.as_reader().lines() {
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
        let section = if section_name == "ABS" {
            None
        } else if let Some((section_index, _)) = obj.sections.by_name(&section_name)? {
            Some(section_index)
        } else if obj.kind == ObjKind::Executable {
            let (section_index, section) = obj.sections.at_address_mut(addr)?;
            if !section.section_known {
                section.rename(section_name)?;
            }
            Some(section_index)
        } else {
            bail!("Section {} not found", section_name)
        };
        let demangled_name = demangle(&name, &DemangleOptions::default());
        let mut symbol =
            ObjSymbol { name, demangled_name, address: addr as u64, section, ..Default::default() };
        // TODO move somewhere common
        if symbol.name.starts_with("..") {
            symbol.flags.0 |= ObjSymbolFlags::ForceActive;
        }
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
                    "hash" => {
                        let hash = parse_hex(value)?;
                        symbol.name_hash = Some(hash);
                        if symbol.demangled_name_hash.is_none() {
                            symbol.demangled_name_hash = Some(hash);
                        }
                    }
                    "dhash" => {
                        symbol.demangled_name_hash = Some(parse_hex(value)?);
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
                        ensure!(
                            section.is_some(),
                            "Symbol {} requires section with noreloc",
                            symbol.name
                        );
                        let addr = SectionAddress::new(section.unwrap(), symbol.address as u32);
                        obj.blocked_ranges.insert(addr, addr.address + symbol.size as u32);
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

pub fn is_skip_symbol(symbol: &ObjSymbol) -> bool {
    if symbol.flags.is_no_write() {
        return true;
    }
    // symbol.name.starts_with("lbl_")
    //     || symbol.name.starts_with("func_")
    //     || symbol.name.starts_with("switch_")
    //     || symbol.name.starts_with("float_")
    //     || symbol.name.starts_with("double_")
    false
}

pub fn is_auto_symbol(symbol: &ObjSymbol) -> bool {
    symbol.name.starts_with("lbl_")
        || symbol.name.starts_with("fn_")
        || symbol.name.starts_with("jumptable_")
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
        if symbol.kind == ObjSymbolKind::Section || is_skip_symbol(symbol) {
            continue;
        }
        write_symbol(w, obj, symbol)?;
    }
    Ok(())
}

fn write_symbol<W: Write>(w: &mut W, obj: &ObjInfo, symbol: &ObjSymbol) -> Result<()> {
    write!(w, "{} = ", symbol.name)?;
    let section = symbol.section.and_then(|idx| obj.sections.get(idx));
    if let Some(section) = section {
        write!(w, "{}:", section.name)?;
    }
    write!(w, "{:#010X}; //", symbol.address)?;
    write!(w, " type:{}", symbol_kind_to_str(symbol.kind))?;
    if symbol.size_known && symbol.size > 0 {
        write!(w, " size:{:#X}", symbol.size)?;
    }
    if let Some(scope) = symbol_flags_to_str(symbol.flags) {
        write!(w, " scope:{scope}")?;
    }
    if let Some(align) = symbol.align {
        write!(w, " align:{align}")?;
    }
    if let Some(kind) = symbol_data_kind_to_str(symbol.data_kind) {
        write!(w, " data:{kind}")?;
    }
    if let Some(hash) = symbol.name_hash {
        write!(w, " hash:{:#010X}", hash)?;
    }
    if let Some(hash) = symbol.demangled_name_hash {
        if symbol.name_hash != symbol.demangled_name_hash {
            write!(w, " dhash:{:#010X}", hash)?;
        }
    }
    if symbol.flags.is_hidden() {
        write!(w, " hidden")?;
    }
    // if symbol.flags.is_force_active() {
    //     write!(w, " force_active")?;
    // }
    if let Some(section) = symbol.section {
        if obj.blocked_ranges.contains_key(&SectionAddress::new(section, symbol.address as u32)) {
            write!(w, " noreloc")?;
        }
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
fn section_kind_from_str(s: &str) -> Option<ObjSectionKind> {
    match s {
        "code" | "text" => Some(ObjSectionKind::Code),
        "data" => Some(ObjSectionKind::Data),
        "rodata" => Some(ObjSectionKind::ReadOnlyData),
        "bss" => Some(ObjSectionKind::Bss),
        _ => None,
    }
}

#[inline]
fn section_kind_to_str(kind: ObjSectionKind) -> &'static str {
    match kind {
        ObjSectionKind::Code => "code",
        ObjSectionKind::Data => "data",
        ObjSectionKind::ReadOnlyData => "rodata",
        ObjSectionKind::Bss => "bss",
    }
}

#[inline]
pub fn write_splits_file<P: AsRef<Path>>(path: P, obj: &ObjInfo, all: bool) -> Result<()> {
    let mut w = buf_writer(path)?;
    write_splits(&mut w, obj, all)?;
    w.flush()?;
    Ok(())
}

pub fn write_splits<W: Write>(w: &mut W, obj: &ObjInfo, all: bool) -> Result<()> {
    writeln!(w, "Sections:")?;
    for (_, section) in obj.sections.iter() {
        write!(w, "\t{:<11} type:{}", section.name, section_kind_to_str(section.kind))?;
        if section.align > 0 {
            write!(w, " align:{}", section.align)?;
        }
        writeln!(w)?;
    }
    for unit in obj.link_order.iter().filter(|unit| all || !unit.autogenerated) {
        write!(w, "\n{}:", unit.name)?;
        if let Some(comment_version) = unit.comment_version {
            write!(w, " comment:{}", comment_version)?;
        }
        writeln!(w)?;
        let mut split_iter = obj.sections.all_splits().peekable();
        while let Some((_section_index, section, addr, split)) = split_iter.next() {
            if split.unit != unit.name {
                continue;
            }
            let end = if split.end > 0 {
                split.end
            } else {
                split_iter.peek().map(|&(_, _, addr, _)| addr).unwrap_or(0)
            };
            write!(w, "\t{:<11} start:{:#010X} end:{:#010X}", section.name, addr, end)?;
            if let Some(align) = split.align {
                if align != default_section_align(section) as u32 {
                    write!(w, " align:{}", align)?;
                }
            }
            if split.common {
                write!(w, " common")?;
            }
            if let Some(name) = &split.rename {
                write!(w, " rename:{}", name)?;
            }
            if split.skip {
                write!(w, " skip")?;
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
    rename: Option<String>,
    skip: bool,
}

struct SplitUnit {
    name: String,
    /// MW `.comment` section version
    comment_version: Option<u8>,
}

pub struct SectionDef {
    pub name: String,
    pub kind: Option<ObjSectionKind>,
    pub align: Option<u32>,
}

enum SplitLine {
    Unit(SplitUnit),
    UnitSection(SplitSection),
    SectionsStart,
    Section(SectionDef),
    None,
}

fn parse_split_line(line: &str, state: &SplitState) -> Result<SplitLine> {
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
        parse_section_line(captures, state)
            .with_context(|| format!("While parsing split line: '{line}'"))
    } else {
        Err(anyhow!("Failed to parse split line: '{line}'"))
    }
}

fn parse_unit_line(captures: Captures) -> Result<SplitLine> {
    let name = &captures["name"];
    if name == "Sections" {
        return Ok(SplitLine::SectionsStart);
    }
    let mut unit = SplitUnit { name: name.to_string(), comment_version: None };

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

fn parse_section_line(captures: Captures, state: &SplitState) -> Result<SplitLine> {
    if matches!(state, SplitState::Sections(_)) {
        let name = &captures["name"];
        let mut section = SectionDef { name: name.to_string(), kind: None, align: None };

        for attr in captures["attrs"].split(' ').filter(|&s| !s.is_empty()) {
            if let Some((attr, value)) = attr.split_once(':') {
                match attr {
                    "type" => {
                        section.kind = Some(
                            section_kind_from_str(value)
                                .ok_or_else(|| anyhow!("Unknown section type '{}'", value))?,
                        );
                    }
                    "align" => {
                        section.align = Some(parse_hex(value)?);
                    }
                    _ => bail!("Unknown section attribute '{attr}'"),
                }
            } else {
                bail!("Unknown section attribute '{attr}'");
            }
        }

        return Ok(SplitLine::Section(section));
    }

    let mut start = None;
    let mut end = None;
    let mut section = SplitSection {
        name: captures["name"].to_string(),
        start: 0,
        end: 0,
        align: None,
        common: false,
        rename: None,
        skip: false,
    };

    for attr in captures["attrs"].split(' ').filter(|&s| !s.is_empty()) {
        if let Some((attr, value)) = attr.split_once(':') {
            match attr {
                "start" => start = Some(parse_hex(value)?),
                "end" => end = Some(parse_hex(value)?),
                "align" => section.align = Some(parse_hex(value)?),
                "rename" => section.rename = Some(value.to_string()),
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
                "skip" => section.skip = true,
                _ => bail!("Unknown split attribute '{attr}'"),
            }
        }
    }
    if let (Some(start), Some(end)) = (start, end) {
        section.start = start;
        section.end = end;
        Ok(SplitLine::UnitSection(section))
    } else {
        Err(anyhow!("Section '{}' missing start or end address", section.name))
    }
}

enum SplitState {
    None,
    Sections(usize),
    Unit(String),
}

pub fn apply_splits_file<P: AsRef<Path>>(path: P, obj: &mut ObjInfo) -> Result<bool> {
    Ok(if path.as_ref().is_file() {
        let file = map_file(path)?;
        apply_splits(file.as_reader(), obj)?;
        true
    } else {
        false
    })
}

pub fn apply_splits<R: BufRead>(r: R, obj: &mut ObjInfo) -> Result<()> {
    let mut state = SplitState::None;
    for result in r.lines() {
        let line = match result {
            Ok(line) => line,
            Err(e) => return Err(e.into()),
        };
        let split_line = parse_split_line(&line, &state)?;
        match (&mut state, split_line) {
            (
                SplitState::None | SplitState::Unit(_) | SplitState::Sections(_),
                SplitLine::Unit(SplitUnit { name, comment_version }),
            ) => {
                obj.link_order.push(ObjUnit {
                    name: name.clone(),
                    autogenerated: false,
                    comment_version,
                });
                state = SplitState::Unit(name);
            }
            (SplitState::None, SplitLine::UnitSection(SplitSection { name, .. })) => {
                bail!("Section {} defined outside of unit", name);
            }
            (SplitState::None | SplitState::Unit(_), SplitLine::SectionsStart) => {
                state = SplitState::Sections(0);
            }
            (SplitState::Sections(index), SplitLine::Section(SectionDef { name, kind, align })) => {
                let Some(obj_section) = obj.sections.get_mut(*index) else {
                    bail!(
                        "Section out of bounds: {} (index {}), object has {} sections",
                        name,
                        index,
                        obj.sections.count()
                    );
                };
                if obj_section.rename(name.clone()).is_err() {
                    // Manual section
                    obj_section.kind =
                        kind.ok_or_else(|| anyhow!("Section '{}' missing type", name))?;
                    obj_section.name = name;
                    obj_section.section_known = true;
                }
                if let Some(align) = align {
                    obj_section.align = align as u64;
                }
                *index += 1;
            }
            (
                SplitState::Unit(unit),
                SplitLine::UnitSection(SplitSection {
                    name,
                    start,
                    end,
                    align,
                    common,
                    rename,
                    skip,
                }),
            ) => {
                let (section_index, _) = match obj.sections.by_name(&name)? {
                    Some(v) => Ok(v),
                    None => {
                        if obj.kind == ObjKind::Executable {
                            obj.sections.with_range(start..end)
                        } else {
                            Err(anyhow!("Section {} not found", name))
                        }
                    }
                }?;
                let section = obj.sections.get_mut(section_index).unwrap();
                let section_end = (section.address + section.size) as u32;
                ensure!(
                    section.contains_range(start..end)
                        || (start == section_end && end == section_end),
                    "Section {} ({:#010X}..{:#010X}) does not contain range {:#010X}..{:#010X}",
                    name,
                    section.address,
                    section.address + section.size,
                    start,
                    end
                );
                section.splits.push(start, ObjSplit {
                    unit: unit.clone(),
                    end,
                    align,
                    common,
                    autogenerated: false,
                    skip,
                    rename,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn read_splits_sections<P: AsRef<Path>>(path: P) -> Result<Option<Vec<SectionDef>>> {
    if !path.as_ref().is_file() {
        return Ok(None);
    }
    let file = map_file(path)?;
    let r = file.as_reader();
    let mut sections = Vec::new();
    let mut state = SplitState::None;
    for result in r.lines() {
        let line = match result {
            Ok(line) => line,
            Err(e) => return Err(e.into()),
        };
        let split_line = parse_split_line(&line, &state)?;
        match (&mut state, split_line) {
            (SplitState::None | SplitState::Unit(_), SplitLine::SectionsStart) => {
                state = SplitState::Sections(0);
            }
            (SplitState::Sections(index), SplitLine::Section(def)) => {
                sections.push(def);
                *index += 1;
            }
            (SplitState::Sections(_), SplitLine::None) => {
                // Continue
            }
            (SplitState::Sections(_), _) => {
                // End of sections
                break;
            }
            _ => {}
        }
    }
    if sections.is_empty() {
        Ok(None)
    } else {
        Ok(Some(sections))
    }
}
