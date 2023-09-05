use std::{
    cmp::Ordering,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use binrw::{binrw, io::NoSeek, BinRead, BinWrite};
use itertools::Itertools;
use object::{elf, Object, ObjectSection, ObjectSymbol};
use tracing::warn;

use crate::{
    array_ref_mut,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
    util::IntoCow,
};

/// Do not relocate anything, but accumulate the offset field for the next relocation offset calculation.
/// These types are used for referring to relocations that are more than 0xffff apart from each other.
pub const R_DOLPHIN_NOP: u32 = 201;
/// Change which section relocations are being applied to.
/// Set the offset into the section to 0.
pub const R_DOLPHIN_SECTION: u32 = 202;
/// Stop parsing the relocation list.
pub const R_DOLPHIN_END: u32 = 203;
/// Unknown.
#[allow(unused)]
pub const R_DOLPHIN_MRKREF: u32 = 204;

#[binrw]
#[derive(Clone, Debug)]
#[br(assert(next == 0))]
#[br(assert(prev == 0))]
#[br(assert(bss_section == 0))]
#[brw(assert(matches!(version, 1..=3), "Unsupported REL version {version}"))]
pub struct RelHeader {
    /// Arbitrary identification number.
    /// Must be unique amongst all RELs used by a game.
    /// 0 is reserved for the DOL.
    pub module_id: u32,
    /// Pointer to next module.
    /// Filled at runtime.
    #[bw(calc = 0)]
    pub next: u32,
    /// Pointer to previous module.
    /// Filled at runtime.
    #[bw(calc = 0)]
    pub prev: u32,
    /// Number of sections in the file.
    pub num_sections: u32,
    /// Offset to the start of the section table.
    pub section_info_offset: u32,
    /// Offset in the external module name string table file.
    pub name_offset: u32,
    /// Size of the module name in bytes.
    pub name_size: u32,
    /// Version number of the REL file format.
    pub version: u32,
    /// Size of the `.bss` section.
    pub bss_size: u32,
    /// Offset to the start of the relocation table.
    pub rel_offset: u32,
    /// Offset to the start of the import table.
    pub imp_offset: u32,
    /// Size of the import table.
    pub imp_size: u32,
    /// Section containing the `_prolog` function.
    pub prolog_section: u8,
    /// Section containing the `_epilog` function.
    pub epilog_section: u8,
    /// Section containing the `_unresolved` function.
    pub unresolved_section: u8,
    /// Index into section table which bss is relative to.
    /// Filled at runtime.
    #[bw(calc = 0)]
    pub bss_section: u8,
    /// Offset into the section containing `_prolog`.
    pub prolog_offset: u32,
    /// Offset into the section containing `_epilog`.
    pub epilog_offset: u32,
    /// Offset into the section containing `_unresolved`.
    pub unresolved_offset: u32,
    /// (Version >= 2 only)
    /// Alignment constraint on all sections.
    #[br(if(version >= 2))]
    #[bw(if(*version >= 2))]
    pub align: Option<u32>,
    /// (Version >= 2 only)
    /// Alignment constraint on the `.bss` section.
    #[br(if(version >= 2))]
    #[bw(if(*version >= 2))]
    pub bss_align: Option<u32>,
    /// (Version >= 3 only)
    /// If REL is linked with `OSLinkFixed` (instead of `OSLink`), the
    /// space after this offset can be used for other purposes, like BSS.
    #[br(if(version >= 3))]
    #[bw(if(*version >= 3))]
    pub fix_size: Option<u32>,
}

#[binrw]
#[derive(Copy, Clone, Debug)]
struct RelImport {
    module_id: u32,
    offset: u32,
}

#[binrw]
#[derive(Copy, Clone, Debug)]
struct RelSectionHeader {
    offset_and_flags: u32,
    size: u32,
}

impl RelSectionHeader {
    fn new(offset: u32, size: u32, exec: bool) -> Self {
        Self { offset_and_flags: offset | (exec as u32), size }
    }

    fn offset(&self) -> u32 { self.offset_and_flags & !1 }

    fn size(&self) -> u32 { self.size }

    fn exec(&self) -> bool { self.offset_and_flags & 1 != 0 }
}

#[binrw]
#[derive(Copy, Clone, Debug)]
struct RelRelocRaw {
    offset: u16,
    kind: u8,
    section: u8,
    addend: u32,
}

pub fn process_rel_header<R: Read + Seek>(reader: &mut R) -> Result<RelHeader> {
    RelHeader::read_be(reader).context("Failed to read REL header")
}

pub fn process_rel<R: Read + Seek>(reader: &mut R, name: &str) -> Result<(RelHeader, ObjInfo)> {
    let header = process_rel_header(reader)?;
    let mut sections = Vec::with_capacity(header.num_sections as usize);
    reader.seek(SeekFrom::Start(header.section_info_offset as u64))?;
    let mut found_text = false;
    let mut total_bss_size = 0;
    for idx in 0..header.num_sections {
        let section = RelSectionHeader::read_be(reader)
            .with_context(|| format!("Failed to read REL section header {}", idx))?;
        let offset = section.offset();
        let size = section.size();
        if size == 0 {
            continue;
        }

        let data = if offset == 0 {
            vec![]
        } else {
            let position = reader.stream_position()?;
            reader.seek(SeekFrom::Start(offset as u64))?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data).with_context(|| {
                format!("Failed to read REL section {} data with size {:#X}", idx, size)
            })?;
            reader.seek(SeekFrom::Start(position))?;
            data
        };

        let (name, kind, section_known) = if offset == 0 {
            ensure!(total_bss_size == 0, "Multiple BSS sections in REL");
            total_bss_size = size;
            (".bss".to_string(), ObjSectionKind::Bss, true)
        } else if section.exec() {
            ensure!(!found_text, "Multiple text sections in REL");
            found_text = true;
            (".text".to_string(), ObjSectionKind::Code, true)
        } else {
            (format!(".section{}", idx), ObjSectionKind::Data, false)
        };
        sections.push(ObjSection {
            name,
            kind,
            address: 0,
            size: size as u64,
            data,
            align: match offset {
                0 => header.bss_align,
                _ => header.align,
            }
            .unwrap_or_default() as u64,
            elf_index: idx as usize,
            relocations: Default::default(),
            original_address: 0,
            file_offset: offset as u64,
            section_known,
            splits: Default::default(),
        });
    }
    ensure!(
        total_bss_size == header.bss_size,
        "Mismatched BSS size: {:#X} != {:#X}",
        total_bss_size,
        header.bss_size
    );

    let mut symbols = Vec::new();
    let mut add_symbol = |rel_section_idx: u8, offset: u32, name: &str| -> Result<()> {
        if rel_section_idx > 0 {
            let (section_index, _) = sections
                .iter()
                .enumerate()
                .find(|&(_, section)| section.elf_index == rel_section_idx as usize)
                .ok_or_else(|| anyhow!("Failed to locate {name} section {rel_section_idx}"))?;
            log::debug!("Adding {name} section {rel_section_idx} offset {offset:#X}");
            symbols.push(ObjSymbol {
                name: name.to_string(),
                demangled_name: None,
                address: offset as u64,
                section: Some(section_index),
                size: 0,
                size_known: false,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                align: None,
                data_kind: Default::default(),
            });
        }
        Ok(())
    };
    add_symbol(header.prolog_section, header.prolog_offset, "_prolog")?;
    add_symbol(header.epilog_section, header.epilog_offset, "_epilog")?;
    add_symbol(header.unresolved_section, header.unresolved_offset, "_unresolved")?;

    let mut unresolved_relocations = Vec::new();
    let mut imp_idx = 0;
    let imp_end = (header.imp_offset + header.imp_size) as u64;
    reader.seek(SeekFrom::Start(header.imp_offset as u64))?;
    while reader.stream_position()? < imp_end {
        let import = RelImport::read_be(reader)?;

        if imp_idx == 0 {
            ensure!(
                import.offset == header.rel_offset,
                "imp index 0 offset mismatch: {:#X} != {:#X}",
                import.offset,
                header.rel_offset
            );
        }
        imp_idx += 1;

        if import.module_id == header.module_id {
            if let Some(fix_size) = header.fix_size {
                ensure!(
                    fix_size == import.offset,
                    "fix_size mismatch: {:#X} != {:#X}",
                    fix_size,
                    import.offset
                );
            }
        }

        let position = reader.stream_position()?;
        reader.seek(SeekFrom::Start(import.offset as u64))?;
        let mut address = 0u32;
        let mut section = u8::MAX;
        loop {
            let reloc = RelRelocRaw::read_be(reader)?;
            let kind = match reloc.kind as u32 {
                elf::R_PPC_NONE => continue,
                elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 => ObjRelocKind::Absolute,
                // elf::R_PPC_ADDR24 => ObjRelocKind::PpcAddr24,
                // elf::R_PPC_ADDR16 => ObjRelocKind::PpcAddr16,
                elf::R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
                elf::R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
                elf::R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
                // elf::R_PPC_ADDR14 => ObjRelocKind::PpcAddr14,
                // elf::R_PPC_ADDR14_BRTAKEN => ObjRelocKind::PpcAddr14BrTaken,
                // elf::R_PPC_ADDR14_BRNTAKEN => ObjRelocKind::PpcAddr14BrnTaken,
                elf::R_PPC_REL24 => ObjRelocKind::PpcRel24,
                elf::R_PPC_REL14 => ObjRelocKind::PpcRel14,
                // elf::R_PPC_REL14_BRTAKEN => ObjRelocKind::PpcRel14BrTaken,
                // elf::R_PPC_REL14_BRNTAKEN => ObjRelocKind::PpcRel14BrnTaken,
                R_DOLPHIN_NOP => {
                    address += reloc.offset as u32;
                    continue;
                }
                R_DOLPHIN_SECTION => {
                    address = 0;
                    section = reloc.section;
                    continue;
                }
                R_DOLPHIN_END => break,
                // R_DOLPHIN_MRKREF => ?
                reloc_type => bail!("Unhandled REL relocation type {reloc_type}"),
            };
            address += reloc.offset as u32;
            let reloc = RelReloc {
                kind,
                section,
                address: address & !3,
                module_id: import.module_id,
                target_section: reloc.section,
                addend: reloc.addend,
            };
            unresolved_relocations.push(reloc);
        }
        reader.seek(SeekFrom::Start(position))?;
    }

    log::debug!("Read REL ID {}", header.module_id);
    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        name.to_string(),
        symbols,
        sections,
    );
    obj.module_id = header.module_id;
    obj.unresolved_relocations = unresolved_relocations;
    Ok((header, obj))
}

/// REL relocation.
#[derive(Debug, Clone)]
pub struct RelReloc {
    /// Relocation kind.
    pub kind: ObjRelocKind,
    /// Source section index.
    pub section: u8,
    /// Source address.
    pub address: u32,
    /// Target module ID.
    pub module_id: u32,
    /// Target section index.
    pub target_section: u8,
    /// Target addend within section.
    /// If target module ID is 0 (DOL), this is an absolute address.
    pub addend: u32,
}

#[inline]
fn reloc_can_be_applied(_module_id: u32, rel_reloc: &RelReloc) -> bool {
    matches!(rel_reloc.kind, ObjRelocKind::PpcRel24 | ObjRelocKind::PpcRel14)
}

#[inline]
fn skip_reloc(module_id: u32, rel_reloc: &RelReloc) -> bool {
    rel_reloc.module_id == module_id
        && rel_reloc.section == rel_reloc.target_section
        && matches!(rel_reloc.kind, ObjRelocKind::PpcRel24 | ObjRelocKind::PpcRel14)
}

fn apply_relocation(
    data: &mut [u8],
    module_id: u32,
    rel_reloc: &RelReloc,
    unresolved: u32,
) -> Result<()> {
    let diff = if rel_reloc.module_id == module_id && rel_reloc.section == rel_reloc.target_section
    {
        rel_reloc.addend as i32 - rel_reloc.address as i32
    } else {
        unresolved as i32 - rel_reloc.address as i32
    };
    let ins_ref = array_ref_mut!(data, rel_reloc.address as usize, 4);
    let mut ins = u32::from_be_bytes(*ins_ref);
    match rel_reloc.kind {
        ObjRelocKind::PpcRel24 => {
            ensure!((-0x2000000..0x2000000).contains(&diff), "R_PPC_REL24 relocation out of range");
            ins = (ins & !0x3fffffc) | (diff as u32 & 0x3fffffc);
        }
        ObjRelocKind::PpcRel14 => {
            ensure!((-0x2000..0x2000).contains(&diff), "R_PPC_REL14 relocation out of range");
            ins = (ins & !0xfffc) | (diff as u32 & 0xfffc);
        }
        kind => bail!("Unsupported relocation kind {:?}", kind),
    }
    *ins_ref = ins.to_be_bytes();
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RelWriteInfo {
    /// REL module ID.
    pub module_id: u32,
    /// REL version.
    pub version: u32,
    /// Override `name_offset` in the REL header.
    /// Useful for matching RELs without the original string table.
    pub name_offset: Option<u32>,
    /// Override `name_size` in the REL header.
    /// Useful for matching RELs without the original string table.
    pub name_size: Option<u32>,
    /// Override `align` in the REL header.
    pub align: Option<u32>,
    /// Override `bss_align` in the REL header.
    pub bss_align: Option<u32>,
    /// Override the number of sections in the file.
    /// Useful for matching RELs that included debug sections.
    pub section_count: Option<usize>,
    /// If true, don't print warnings about overriding values.
    pub quiet: bool,
}

const PERMITTED_SECTIONS: [&str; 7] =
    [".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss"];

pub fn should_write_section(section: &object::Section) -> bool {
    matches!(section.name(), Ok(name) if PERMITTED_SECTIONS.contains(&name))
        && section.kind() != object::SectionKind::UninitializedData
}

pub fn write_rel<W: Write>(
    w: &mut W,
    info: &RelWriteInfo,
    file: &object::File,
    mut relocations: Vec<RelReloc>,
) -> Result<()> {
    relocations.sort_by(|a, b| {
        if a.module_id == 0 {
            if b.module_id == 0 {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        } else if a.module_id == info.module_id {
            if b.module_id == 0 {
                Ordering::Less
            } else if b.module_id == info.module_id {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        } else if b.module_id == 0 || b.module_id == info.module_id {
            Ordering::Less
        } else {
            a.module_id.cmp(&b.module_id)
        }
        .then(a.section.cmp(&b.section))
        .then(a.address.cmp(&b.address))
    });

    let mut apply_relocations = vec![];
    relocations.retain(|r| {
        if !should_write_section(
            &file.section_by_index(object::SectionIndex(r.section as usize)).unwrap(),
        ) {
            return false;
        }
        if reloc_can_be_applied(info.module_id, r) {
            apply_relocations.push(r.clone());
            !skip_reloc(info.module_id, r)
        } else {
            true
        }
    });

    let mut align =
        file.sections().filter(should_write_section).map(|s| s.align() as u32).max().unwrap_or(0);
    let bss = file.sections().find(|s| s.name() == Ok(".bss"));
    let mut bss_align = bss.as_ref().map(|s| s.align() as u32).unwrap_or(1);
    let mut num_sections = file.sections().count() as u32;

    // Apply overrides
    if let Some(section_count) = info.section_count {
        if section_count != num_sections as usize && !info.quiet {
            warn!(from = num_sections, to = section_count, "Overriding section count");
        }
        num_sections = section_count as u32;
    }
    if info.version >= 2 {
        if let Some(align_override) = info.align {
            if align_override != align && !info.quiet {
                warn!(from = align, to = align_override, "Overriding alignment");
            }
            align = align_override;
        }
        if let Some(bss_align_override) = info.bss_align {
            if bss_align_override != bss_align && !info.quiet {
                warn!(from = bss_align, to = bss_align_override, "Overriding BSS alignment");
            }
            bss_align = bss_align_override;
        }
    }

    let mut header = RelHeader {
        module_id: info.module_id,
        num_sections,
        section_info_offset: match info.version {
            1 => 0x40,
            2 => 0x48,
            3 => 0x4C,
            _ => bail!("Unsupported REL version {}", info.version),
        },
        name_offset: info.name_offset.unwrap_or(0),
        name_size: info.name_size.unwrap_or(0),
        version: info.version,
        bss_size: bss.as_ref().map(|s| s.size() as u32).unwrap_or(0),
        rel_offset: 0,
        imp_offset: 0,
        imp_size: 0,
        prolog_section: 0,
        epilog_section: 0,
        unresolved_section: 0,
        prolog_offset: 0,
        epilog_offset: 0,
        unresolved_offset: 0,
        align: if info.version >= 2 { Some(align) } else { None },
        bss_align: if info.version >= 2 { Some(bss_align) } else { None },
        fix_size: None,
    };
    let mut offset = header.section_info_offset;
    offset += num_sections * 8;
    let section_data_offset = offset;
    for section in file.sections().filter(should_write_section) {
        let align = section.align() as u32 - 1;
        offset = (offset + align) & !align;
        offset += section.size() as u32;
    }
    header.imp_offset = offset;
    let imp_count = relocations.iter().map(|r| r.module_id).dedup().count();
    header.imp_size = imp_count as u32 * 8;
    offset += header.imp_size;
    header.rel_offset = offset;

    let mut imp_entries = Vec::<RelImport>::with_capacity(imp_count);
    let mut raw_relocations = vec![];
    {
        let mut address = 0u32;
        let mut section = u8::MAX;
        let mut last_module_id = u32::MAX;
        for reloc in &relocations {
            if reloc.module_id != last_module_id {
                if last_module_id != u32::MAX {
                    raw_relocations.push(RelRelocRaw {
                        offset: 0,
                        kind: R_DOLPHIN_END as u8,
                        section: 0,
                        addend: 0,
                    });
                    offset += 8;
                }
                imp_entries.push(RelImport { module_id: reloc.module_id, offset });
                section = u8::MAX;
                last_module_id = reloc.module_id;
            }
            if info.version >= 3
                && header.fix_size.is_none()
                && (reloc.module_id == 0 || reloc.module_id == info.module_id)
            {
                header.fix_size = Some(offset);
            }
            if reloc.section != section {
                raw_relocations.push(RelRelocRaw {
                    offset: 0,
                    kind: R_DOLPHIN_SECTION as u8,
                    section: reloc.section,
                    addend: 0,
                });
                offset += 8;
                address = 0;
                section = reloc.section;
            }
            let mut reloc_offset = reloc.address - address;
            while reloc_offset > 0xffff {
                raw_relocations.push(RelRelocRaw {
                    offset: 0xffff,
                    kind: R_DOLPHIN_NOP as u8,
                    section: 0,
                    addend: 0,
                });
                offset += 8;
                reloc_offset -= 0xffff;
            }
            raw_relocations.push(RelRelocRaw {
                offset: reloc_offset as u16,
                kind: match reloc.kind {
                    ObjRelocKind::Absolute => elf::R_PPC_ADDR32,
                    ObjRelocKind::PpcAddr16Lo => elf::R_PPC_ADDR16_LO,
                    ObjRelocKind::PpcAddr16Hi => elf::R_PPC_ADDR16_HI,
                    ObjRelocKind::PpcAddr16Ha => elf::R_PPC_ADDR16_HA,
                    ObjRelocKind::PpcRel24 => elf::R_PPC_REL24,
                    ObjRelocKind::PpcRel14 => elf::R_PPC_REL14,
                    _ => bail!("Unsupported relocation kind {:?}", reloc.kind),
                } as u8,
                section: reloc.target_section,
                addend: reloc.addend,
            });
            address = reloc.address;
            offset += 8;
        }
    }
    raw_relocations.push(RelRelocRaw {
        offset: 0,
        kind: R_DOLPHIN_END as u8,
        section: 0,
        addend: 0,
    });
    offset += 8;

    for symbol in file.symbols().filter(|s| s.is_definition()) {
        let Some(symbol_section) = symbol.section_index() else {
            continue;
        };
        match symbol.name() {
            Ok("_prolog") => {
                header.prolog_section = symbol_section.0 as u8;
                header.prolog_offset = symbol.address() as u32;
            }
            Ok("_epilog") => {
                header.epilog_section = symbol_section.0 as u8;
                header.epilog_offset = symbol.address() as u32;
            }
            Ok("_unresolved") => {
                header.unresolved_section = symbol_section.0 as u8;
                header.unresolved_offset = symbol.address() as u32;
            }
            _ => {}
        }
    }

    let mut w = NoSeek::new(w);
    header.write_be(&mut w)?;
    ensure!(w.stream_position()? as u32 == header.section_info_offset);
    let mut current_data_offset = section_data_offset;
    for section_index in 0..num_sections {
        let Ok(section) = file.section_by_index(object::SectionIndex(section_index as usize))
        else {
            RelSectionHeader::new(0, 0, false).write_be(&mut w)?;
            continue;
        };
        if matches!(section.name(), Ok(name) if PERMITTED_SECTIONS.contains(&name)) {
            let mut offset = 0;
            if section.kind() != object::SectionKind::UninitializedData {
                let align = section.align() as u32 - 1;
                current_data_offset = (current_data_offset + align) & !align;
                offset = current_data_offset;
                current_data_offset += section.size() as u32;
            }
            RelSectionHeader::new(
                offset,
                section.size() as u32,
                section.kind() == object::SectionKind::Text,
            )
            .write_be(&mut w)?;
        } else {
            RelSectionHeader::new(0, 0, false).write_be(&mut w)?;
        }
    }
    ensure!(w.stream_position()? as u32 == section_data_offset);
    for section in file.sections().filter(should_write_section) {
        fn calculate_padding(position: u64, align: u64) -> u64 {
            let align = align - 1;
            ((position + align) & !align) - position
        }
        let position = w.stream_position()?;
        w.write_all(&vec![0; calculate_padding(position, section.align()) as usize])?;

        let section_index = section.index().0 as u8;
        let mut section_data = section.uncompressed_data()?;
        if apply_relocations.iter().any(|r| r.section == section_index) {
            let mut data = section_data.into_owned();
            for reloc in apply_relocations.iter().filter(|r| r.section == section_index) {
                apply_relocation(&mut data, info.module_id, reloc, header.unresolved_offset)?;
            }
            section_data = data.into_cow();
        }
        w.write_all(&section_data)?;
    }
    ensure!(w.stream_position()? as u32 == header.imp_offset);
    for entry in imp_entries {
        entry.write_be(&mut w)?;
    }
    ensure!(w.stream_position()? as u32 == header.rel_offset);
    for reloc in raw_relocations {
        reloc.write_be(&mut w)?;
    }
    ensure!(w.stream_position()? as u32 == offset);
    Ok(())
}
