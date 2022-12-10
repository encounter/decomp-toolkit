use std::{
    cmp::{min, Ordering},
    collections::{btree_map, hash_map::Entry, BTreeMap, HashMap},
    fmt::Display,
    fs,
    fs::{DirBuilder, File},
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::{Error, Result};
use ppc750cl::{disasm_iter, Argument, Ins, Opcode};

use crate::util::obj::{
    ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlags,
    ObjSymbolKind,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SymbolEntryKind {
    Start,
    End,
    Label,
}

#[derive(Debug, Copy, Clone)]
struct SymbolEntry {
    index: usize,
    kind: SymbolEntryKind,
}

pub fn write_asm<P: AsRef<Path> + Display>(path: P, obj: &ObjInfo) -> Result<()> {
    let mut file_map = HashMap::<String, BufWriter<File>>::new();

    let asm_dir = path.as_ref().join("asm");
    let include_dir = path.as_ref().join("include");
    DirBuilder::new().recursive(true).create(&include_dir)?;
    fs::write(&include_dir.join("macros.inc"), include_bytes!("../../assets/macros.inc"))?;

    for unit in &obj.link_order {
        let w = match file_map.entry(unit.clone()) {
            Entry::Occupied(_) => {
                return Err(Error::msg(format!("Duplicate file {unit}")));
            }
            Entry::Vacant(e) => {
                let file_path = asm_dir.join(file_name_from_unit(unit));
                if let Some(parent) = file_path.parent() {
                    DirBuilder::new().recursive(true).create(parent)?;
                }
                e.insert(BufWriter::new(File::create(file_path)?))
            }
        };
        writeln!(w, ".include \"macros.inc\"")?;
        writeln!(w, ".file \"{}\"", unit.replace('\\', "\\\\"))?;
    }

    let mut symbols = Vec::<ObjSymbol>::new();
    let mut addr_sym = BTreeMap::<u32, Vec<SymbolEntry>>::new();
    for section in &obj.sections {
        for symbol in &section.symbols {
            let symbol_index = symbols.len();
            symbols.push(symbol.clone());
            let symbol_start = symbol.address as u32;
            let symbol_end = (symbol.address + symbol.size) as u32;
            if symbol.size > 0 {
                match addr_sym.entry(symbol_start) {
                    btree_map::Entry::Occupied(mut e) => {
                        e.get_mut().push(SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::Start,
                        });
                    }
                    btree_map::Entry::Vacant(e) => {
                        e.insert(vec![SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::Start,
                        }]);
                    }
                }
                match addr_sym.entry(symbol_end) {
                    btree_map::Entry::Occupied(mut e) => {
                        // Always push first
                        e.get_mut().insert(0, SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::End,
                        });
                    }
                    btree_map::Entry::Vacant(e) => {
                        e.insert(vec![SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::End,
                        }]);
                    }
                }
            } else {
                match addr_sym.entry(symbol_start) {
                    btree_map::Entry::Occupied(mut e) => {
                        e.get_mut().push(SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::Label,
                        });
                    }
                    btree_map::Entry::Vacant(e) => {
                        e.insert(vec![SymbolEntry {
                            index: symbol_index,
                            kind: SymbolEntryKind::Label,
                        }]);
                    }
                }
            }
        }

        // Generate labels for .text relocations
        for reloc in &section.relocations {
            let target_section = match &reloc.target_section {
                Some(v) => v,
                None => continue,
            };
            let section = match obj.sections.iter().find(|s| &s.name == target_section) {
                Some(v) => v,
                None => continue,
            };
            match section.kind {
                ObjSectionKind::Code => {}
                _ => continue,
            }
            if reloc.target.addend == 0 {
                continue;
            }
            let address = (reloc.target.address as i64 + reloc.target.addend) as u64;
            let vec = match addr_sym.entry(address as u32) {
                btree_map::Entry::Occupied(e) => e.into_mut(),
                btree_map::Entry::Vacant(e) => e.insert(vec![]),
            };
            if !vec
                .iter()
                .any(|e| e.kind == SymbolEntryKind::Label || e.kind == SymbolEntryKind::Start)
            {
                let symbol_index = symbols.len();
                symbols.push(ObjSymbol {
                    name: format!(".L_{address:8X}"),
                    demangled_name: None,
                    address,
                    section_address: address - section.address,
                    size: 0,
                    size_known: true,
                    flags: Default::default(),
                    addend: 0,
                    kind: ObjSymbolKind::Unknown,
                });
                vec.push(SymbolEntry { index: symbol_index, kind: SymbolEntryKind::Label });
            }
        }

        // Generate local jump labels
        for ins in disasm_iter(&section.data, section.address as u32) {
            if let Some(address) = ins.branch_dest() {
                let section =
                    match obj.sections.iter().find(|s| {
                        s.address <= address as u64 && (s.address + s.size) > address as u64
                    }) {
                        Some(s) => s,
                        None => continue,
                    };
                let vec = match addr_sym.entry(address) {
                    btree_map::Entry::Occupied(e) => e.into_mut(),
                    btree_map::Entry::Vacant(e) => e.insert(vec![]),
                };
                if !vec
                    .iter()
                    .any(|e| e.kind == SymbolEntryKind::Label || e.kind == SymbolEntryKind::Start)
                {
                    let symbol_index = symbols.len();
                    symbols.push(ObjSymbol {
                        name: format!(".L_{address:8X}"),
                        demangled_name: None,
                        address: address as u64,
                        section_address: address as u64 - section.address,
                        size: 0,
                        size_known: true,
                        flags: Default::default(),
                        addend: 0,
                        kind: ObjSymbolKind::Unknown,
                    });
                    vec.push(SymbolEntry { index: symbol_index, kind: SymbolEntryKind::Label });
                }
            }
        }
    }

    for section in &obj.sections {
        log::info!(
            "Writing section {} ({:#10X} - {:#10X})",
            section.name,
            section.address,
            section.address + section.size
        );

        let mut current_address = section.address as u32;
        let section_end = (section.address + section.size) as u32;
        let mut file_iter = obj.splits.range(current_address..).peekable();

        let mut relocations = BTreeMap::<u32, ObjReloc>::new();
        for reloc in &section.relocations {
            let address = reloc.address as u32;
            match relocations.entry(address) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(reloc.clone());
                }
                btree_map::Entry::Occupied(_) => {
                    return Err(Error::msg(format!("Duplicate relocation @ {address:#10X}")));
                }
            }
        }

        let mut subsection = 0;
        let mut current_unit = String::new();
        loop {
            if current_address >= section_end {
                break;
            }

            let (file_addr, unit) = match file_iter.next() {
                Some((addr, unit)) => (*addr, unit),
                None => return Err(Error::msg("No file found")),
            };
            if file_addr > current_address {
                return Err(Error::msg(format!(
                    "Gap in files: {} @ {:#10X}, {} @ {:#10X}",
                    section.name, section.address, unit, file_addr
                )));
            }
            let mut file_end = section_end;
            if let Some((next_addr, _)) = file_iter.peek() {
                file_end = min(**next_addr, section_end);
            }
            if unit == &current_unit {
                subsection += 1;
            } else {
                current_unit = unit.clone();
                subsection = 0;
            }

            let w = write_section_header(
                &mut file_map,
                unit,
                section,
                subsection,
                current_address,
                file_end,
            )?;
            match section.kind {
                ObjSectionKind::Code | ObjSectionKind::Data => {
                    write_data(
                        w,
                        &symbols,
                        &addr_sym,
                        &relocations,
                        section,
                        current_address,
                        file_end,
                    )?;
                }
                ObjSectionKind::Bss => {
                    write_bss(w, &symbols, &addr_sym, current_address, file_end)?;
                }
            }
            current_address = file_end;
        }
    }

    for (_, mut w) in file_map {
        w.flush()?;
    }
    Ok(())
}

fn write_code_chunk(
    w: &mut BufWriter<File>,
    symbols: &[ObjSymbol],
    sym_map: &BTreeMap<u32, Vec<SymbolEntry>>,
    relocations: &BTreeMap<u32, ObjReloc>,
    section: &ObjSection,
    address: u32,
    data: &[u8],
) -> Result<()> {
    for ins in disasm_iter(data, address) {
        let mut reloc = relocations.get(&ins.addr);
        let mut generated_reloc: Option<ObjReloc> = None;

        // HACK: GCC-built objects generate section-relative jump relocations,
        // which aren't always possible to express in GNU assembler accurately,
        // specifically when dealing with multiple sections with the same name.
        // Use a (hacky) heuristic to clear them so we generate a local label jump below.
        if let Some(rel) = reloc {
            if rel.target.addend != 0
                && matches!(rel.kind, ObjRelocKind::PpcRel14 | ObjRelocKind::PpcRel24)
            {
                reloc = None;
            }
        }

        // If this is a branch instruction, automatically "relocate" to a label.
        // Local branch labels are generated above.
        if reloc.is_none() {
            if let Some(symbol_entry) =
                ins.branch_dest().and_then(|dest| sym_map.get(&dest)).and_then(|entries| {
                    entries
                        .iter()
                        .find(|e| e.kind == SymbolEntryKind::Label)
                        .or_else(|| entries.iter().find(|e| e.kind == SymbolEntryKind::Start))
                })
            {
                let symbol = &symbols[symbol_entry.index];
                generated_reloc = Some(ObjReloc {
                    kind: ObjRelocKind::Absolute,
                    address: ins.addr as u64,
                    target: symbol.clone(),
                    target_section: None,
                });
            }
        }

        let file_offset = section.file_offset + (ins.addr as u64 - section.address);
        write_ins(w, ins, reloc.or(generated_reloc.as_ref()), file_offset)?;
    }
    Ok(())
}

fn write_ins(
    w: &mut BufWriter<File>,
    ins: Ins,
    reloc: Option<&ObjReloc>,
    file_offset: u64,
) -> Result<()> {
    write!(
        w,
        "/* {:08X} {:08X}  {:02X} {:02X} {:02X} {:02X} */\t",
        ins.addr,
        file_offset,
        (ins.code >> 24) & 0xFF,
        (ins.code >> 16) & 0xFF,
        (ins.code >> 8) & 0xFF,
        ins.code & 0xFF
    )?;

    if ins.op == Opcode::Illegal {
        write!(w, ".4byte {:#010X} /* invalid */", ins.code)?;
    } else if is_illegal_instruction(ins.code) {
        let sins = ins.simplified();
        write!(w, ".4byte {:#010X} /* illegal: {} */", sins.ins.code, sins)?;
    } else {
        let sins = ins.simplified();
        write!(w, "{}{}", sins.mnemonic, sins.ins.suffix())?;

        let mut writing_offset = false;
        for (i, arg) in sins.args.iter().enumerate() {
            if !writing_offset {
                if i == 0 {
                    write!(w, " ")?;
                } else {
                    write!(w, ", ")?;
                }
            }
            match arg {
                Argument::Uimm(_) | Argument::Simm(_) | Argument::BranchDest(_) => {
                    if let Some(reloc) = reloc {
                        write_reloc(w, reloc)?;
                    } else {
                        write!(w, "{arg}")?;
                    }
                }
                Argument::Offset(_) => {
                    if let Some(reloc) = reloc {
                        write_reloc(w, reloc)?;
                    } else {
                        write!(w, "{arg}")?;
                    }
                    write!(w, "(")?;
                    writing_offset = true;
                    continue;
                }
                _ => {
                    write!(w, "{arg}")?;
                }
            }
            if writing_offset {
                write!(w, ")")?;
                writing_offset = false;
            }
        }
    }
    writeln!(w)?;
    Ok(())
}

fn write_reloc(w: &mut BufWriter<File>, reloc: &ObjReloc) -> Result<()> {
    write_symbol(w, &reloc.target)?;
    match reloc.kind {
        ObjRelocKind::Absolute | ObjRelocKind::PpcRel24 | ObjRelocKind::PpcRel14 => {
            // pass
        }
        ObjRelocKind::PpcAddr16Hi => {
            write!(w, "@h")?;
        }
        ObjRelocKind::PpcAddr16Ha => {
            write!(w, "@ha")?;
        }
        ObjRelocKind::PpcAddr16Lo => {
            write!(w, "@l")?;
        }
        ObjRelocKind::PpcEmbSda21 => {
            write!(w, "@sda21")?;
        }
    }
    Ok(())
}

fn write_symbol_entry(
    w: &mut BufWriter<File>,
    symbols: &[ObjSymbol],
    entry: &SymbolEntry,
) -> Result<()> {
    let symbol = &symbols[entry.index];
    assert_eq!(symbol.addend, 0);

    // Skip writing certain symbols
    if is_skip_symbol(&symbol.name) {
        return Ok(());
    }

    // Comment out linker-generated symbols
    let mut start_newline = true;
    if entry.kind == SymbolEntryKind::Start && is_linker_symbol(&symbol.name) {
        writeln!(w, "\n/* Linker generated")?;
        start_newline = false;
    }

    let symbol_kind = match symbol.kind {
        ObjSymbolKind::Function => "fn",
        ObjSymbolKind::Object => "obj",
        ObjSymbolKind::Unknown => "sym",
    };
    let visibility = if symbol.flags.0.contains(ObjSymbolFlags::Weak) {
        "weak"
    } else if symbol.flags.0.contains(ObjSymbolFlags::Global) {
        "global"
    } else {
        "local"
    };

    match entry.kind {
        SymbolEntryKind::Label => {
            if symbol.name.starts_with(".L") {
                write_symbol_name(w, &symbol.name)?;
                writeln!(w, ":")?;
            } else {
                write!(w, ".sym ")?;
                write_symbol_name(w, &symbol.name)?;
                writeln!(w, ", {visibility}")?;
            }
        }
        SymbolEntryKind::Start => {
            if start_newline {
                writeln!(w)?;
            }
            if let Some(name) = &symbol.demangled_name {
                writeln!(w, "# {name}")?;
            }
            write!(w, ".{symbol_kind} ")?;
            write_symbol_name(w, &symbol.name)?;
            writeln!(w, ", {visibility}")?;
        }
        SymbolEntryKind::End => {
            write!(w, ".end{symbol_kind} ")?;
            write_symbol_name(w, &symbol.name)?;
            writeln!(w)?;
        }
    }

    if entry.kind == SymbolEntryKind::End && is_linker_symbol(&symbol.name) {
        writeln!(w, "*/")?;
    }
    Ok(())
}

fn write_data(
    w: &mut BufWriter<File>,
    symbols: &[ObjSymbol],
    sym_map: &BTreeMap<u32, Vec<SymbolEntry>>,
    relocations: &BTreeMap<u32, ObjReloc>,
    section: &ObjSection,
    start: u32,
    end: u32,
) -> Result<()> {
    let mut sym_iter = sym_map.range(start..end);
    let mut reloc_iter = relocations.range(start..end);

    let mut current_address = start;
    let mut current_symbol_kind = ObjSymbolKind::Unknown;
    let mut sym = sym_iter.next();
    let mut reloc = reloc_iter.next();
    let mut begin = true;
    loop {
        if current_address == end {
            break;
        }
        if let Some((sym_addr, vec)) = sym {
            if current_address == *sym_addr {
                for entry in vec {
                    if entry.kind == SymbolEntryKind::End && begin {
                        continue;
                    }
                    write_symbol_entry(w, symbols, entry)?;
                }
                current_symbol_kind = find_symbol_kind(current_symbol_kind, symbols, vec)?;
                sym = sym_iter.next();
            }
        }
        begin = false;

        let symbol_kind = if current_symbol_kind == ObjSymbolKind::Unknown {
            match section.kind {
                ObjSectionKind::Code => ObjSymbolKind::Function,
                ObjSectionKind::Data | ObjSectionKind::Bss => ObjSymbolKind::Object,
            }
        } else {
            current_symbol_kind
        };
        if let Some((reloc_addr, r)) = reloc {
            if current_address == *reloc_addr {
                reloc = reloc_iter.next();
                match symbol_kind {
                    ObjSymbolKind::Object => {
                        current_address = write_data_reloc(w, symbols, sym_map, r)?;
                        continue;
                    }
                    ObjSymbolKind::Function => {
                        // handled in write_code_chunk
                    }
                    ObjSymbolKind::Unknown => unreachable!(),
                }
            }
        }

        let until = match (sym, reloc) {
            (Some((sym_addr, _)), Some((reloc_addr, _))) => min(*reloc_addr, *sym_addr),
            (Some((addr, _)), None) | (None, Some((addr, _))) => *addr,
            (None, None) => end,
        };
        let data = &section.data[(current_address - section.address as u32) as usize
            ..(until - section.address as u32) as usize];
        if symbol_kind == ObjSymbolKind::Function {
            if current_address & 3 != 0 || data.len() & 3 != 0 {
                return Err(Error::msg(format!(
                    "Unaligned code write @ {:#010X} size {:#X}",
                    current_address,
                    data.len()
                )));
            }
            write_code_chunk(w, symbols, sym_map, relocations, section, current_address, data)?;
        } else {
            write_data_chunk(w, data)?;
        }
        current_address = until;
    }

    // Write end of symbols
    if let Some(entries) = sym_map.get(&end) {
        for entry in entries {
            if entry.kind != SymbolEntryKind::End {
                continue;
            }
            write_symbol_entry(w, symbols, entry)?;
        }
    }
    Ok(())
}

fn find_symbol_kind(
    current: ObjSymbolKind,
    symbols: &[ObjSymbol],
    entries: &Vec<SymbolEntry>,
) -> Result<ObjSymbolKind> {
    let mut kind = current;
    let mut found = false;
    for entry in entries {
        match entry.kind {
            SymbolEntryKind::Start => {
                let new_kind = symbols[entry.index].kind;
                if new_kind != ObjSymbolKind::Unknown {
                    if found && new_kind != kind {
                        return Err(Error::msg(format!(
                            "Conflicting symbol kinds found: {kind:?} and {new_kind:?}"
                        )));
                    }
                    kind = new_kind;
                    found = true;
                }
            }
            _ => continue,
        }
    }
    Ok(kind)
}

fn write_data_chunk(w: &mut BufWriter<File>, data: &[u8]) -> Result<()> {
    let remain = data;
    for chunk in remain.chunks(4) {
        match chunk.len() {
            4 => {
                let data = u32::from_be_bytes(chunk.try_into().unwrap());
                writeln!(w, "\t.4byte {data:#010X}")?;
            }
            3 => {
                writeln!(w, "\t.byte {:#04X}, {:#04X}, {:#04X}", chunk[0], chunk[1], chunk[2])?;
            }
            2 => {
                writeln!(w, "\t.2byte {:#06X}", u16::from_be_bytes(chunk.try_into().unwrap()))?;
            }
            1 => {
                writeln!(w, "\t.byte {:#04X}", chunk[0])?;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn write_data_reloc(
    w: &mut BufWriter<File>,
    symbols: &[ObjSymbol],
    sym_map: &BTreeMap<u32, Vec<SymbolEntry>>,
    reloc: &ObjReloc,
) -> Result<u32> {
    Ok(match reloc.kind {
        ObjRelocKind::Absolute => {
            // Attempt to use .rel macro for relative relocations
            if reloc.target.addend != 0 {
                let target_addr = (reloc.target.address as i64 + reloc.target.addend) as u32;
                if let Some(entry) = sym_map
                    .get(&target_addr)
                    .and_then(|entries| entries.iter().find(|e| e.kind == SymbolEntryKind::Label))
                {
                    let symbol = &symbols[entry.index];
                    write!(w, "\t.rel ")?;
                    write_symbol_name(w, &reloc.target.name)?;
                    write!(w, ", ")?;
                    write_symbol_name(w, &symbol.name)?;
                    writeln!(w)?;
                    return Ok((reloc.address + 4) as u32);
                }
            }
            write!(w, "\t.4byte ")?;
            write_symbol(w, &reloc.target)?;
            writeln!(w)?;
            (reloc.address + 4) as u32
        }
        _ => todo!(),
    })
}

fn write_bss(
    w: &mut BufWriter<File>,
    symbols: &[ObjSymbol],
    sym_map: &BTreeMap<u32, Vec<SymbolEntry>>,
    start: u32,
    end: u32,
) -> Result<()> {
    let mut sym_iter = sym_map.range(start..end);

    let mut current_address = start;
    let mut sym = sym_iter.next();
    let mut begin = true;
    loop {
        if current_address == end {
            break;
        }
        if let Some((sym_addr, vec)) = sym {
            if current_address == *sym_addr {
                for entry in vec {
                    if entry.kind == SymbolEntryKind::End && begin {
                        continue;
                    }
                    write_symbol_entry(w, symbols, entry)?;
                }
                sym = sym_iter.next();
            }
        }
        begin = false;

        let until = sym.map(|(addr, _)| *addr).unwrap_or(end);
        let size = until - current_address;
        if size > 0 {
            writeln!(w, "\t.skip {size:#X}")?;
        }
        current_address = until;
    }

    // Write end of symbols
    if let Some(entries) = sym_map.get(&end) {
        for entry in entries {
            if entry.kind != SymbolEntryKind::End {
                continue;
            }
            write_symbol_entry(w, symbols, entry)?;
        }
    }
    Ok(())
}

fn file_name_from_unit(str: &str) -> String {
    let str = str.strip_prefix("C:").unwrap_or(str);
    let str = str
        .strip_suffix(".c")
        .or_else(|| str.strip_suffix(".cp"))
        .or_else(|| str.strip_suffix(".cpp"))
        .or_else(|| str.strip_suffix(".s"))
        .unwrap_or(str);
    let str = str.replace('\\', "/");
    format!("{}.s", str.strip_prefix('/').unwrap_or(&str))
}

fn write_section_header<'a>(
    file_map: &'a mut HashMap<String, BufWriter<File>>,
    unit: &String,
    section: &ObjSection,
    subsection: usize,
    start: u32,
    end: u32,
) -> Result<&'a mut BufWriter<File>> {
    let w = file_map
        .get_mut(unit)
        .ok_or_else(|| Error::msg(format!("Failed to locate file for {unit}")))?;
    writeln!(w, "\n# {start:#10X} - {end:#10X}")?;
    let alignment = match section.name.as_str() {
        ".text" if subsection == 0 => {
            write!(w, "{}", section.name)?;
            4
        }
        ".data" | ".bss" | ".rodata" if subsection == 0 => {
            write!(w, "{}", section.name)?;
            8
        }
        ".text" | ".init" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"ax\"")?;
            4
        }
        ".data" | ".sdata" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"wa\"")?;
            8
        }
        ".rodata" | ".sdata2" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"a\"")?;
            8
        }
        ".bss" | ".sbss" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"wa\", @nobits")?;
            8
        }
        ".sbss2" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"a\", @nobits")?;
            8
        }
        ".ctors" | ".dtors" | "extab" | "extabindex" => {
            write!(w, ".section {}", section.name)?;
            write!(w, ", \"a\"")?;
            4
        }
        name => todo!("Section {}", name),
    };
    if subsection != 0 {
        write!(w, ", unique, {subsection}")?;
    }
    writeln!(w)?;
    if alignment != 0 {
        writeln!(w, ".balign {alignment}")?;
    }
    Ok(w)
}

fn write_symbol(w: &mut BufWriter<File>, sym: &ObjSymbol) -> std::io::Result<()> {
    write_symbol_name(w, &sym.name)?;
    match sym.addend.cmp(&0i64) {
        Ordering::Greater => write!(w, "+{:#X}", sym.addend),
        Ordering::Less => write!(w, "-{:#X}", -sym.addend),
        Ordering::Equal => Ok(()),
    }
}

fn write_symbol_name(w: &mut BufWriter<File>, name: &str) -> std::io::Result<()> {
    // TODO more?
    if name.contains('@') || name.contains('<') {
        write!(w, "\"{name}\"")?;
    } else {
        write!(w, "{name}")?;
    }
    Ok(())
}

#[inline]
fn is_skip_symbol(name: &str) -> bool {
    // Avoid generating these, they span across files
    matches!(name, "_ctors" | "_dtors")
}

#[inline]
fn is_linker_symbol(name: &str) -> bool {
    matches!(name, "_eti_init_info" | "_rom_copy_info" | "_bss_init_info")
}

#[inline]
fn is_illegal_instruction(code: u32) -> bool {
    matches!(code, 0x43000000 /* bc 24, lt, 0x0 */ | 0xB8030000 /* lmw r0, 0(r3) */)
}
