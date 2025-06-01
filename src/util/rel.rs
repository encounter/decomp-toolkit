use std::{
    cmp::Ordering,
    io,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use itertools::Itertools;
use object::{elf, Object, ObjectSection, ObjectSymbol};
use tracing::warn;

use crate::{
    array_ref_mut,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
    util::{
        align_up,
        reader::{struct_size, Endian, FromReader, ToWriter, DYNAMIC_SIZE},
        split::default_section_align,
        IntoCow,
    },
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

#[derive(Clone, Debug)]
pub struct RelHeader {
    /// Arbitrary identification number.
    /// Must be unique amongst all RELs used by a game.
    /// 0 is reserved for the DOL.
    pub module_id: u32,
    /// Pointer to next module.
    /// Filled at runtime.
    // pub next: u32,
    /// Pointer to previous module.
    /// Filled at runtime.
    // pub prev: u32,
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
    // pub bss_section: u8,
    /// Offset into the section containing `_prolog`.
    pub prolog_offset: u32,
    /// Offset into the section containing `_epilog`.
    pub epilog_offset: u32,
    /// Offset into the section containing `_unresolved`.
    pub unresolved_offset: u32,
    /// (Version >= 2 only)
    /// Alignment constraint on all sections.
    pub align: Option<u32>,
    /// (Version >= 2 only)
    /// Alignment constraint on the `.bss` section.
    pub bss_align: Option<u32>,
    /// (Version >= 3 only)
    /// If REL is linked with `OSLinkFixed` (instead of `OSLink`), the
    /// space after this offset can be used for other purposes, like BSS.
    pub fix_size: Option<u32>,
}

impl FromReader for RelHeader {
    type Args = ();

    // Differs by version
    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let module_id = u32::from_reader(reader, e)?;
        let next = u32::from_reader(reader, e)?;
        if next != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected next == 0"));
        }
        let prev = u32::from_reader(reader, e)?;
        if prev != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected prev == 0"));
        }
        let num_sections = u32::from_reader(reader, e)?;
        let section_info_offset = u32::from_reader(reader, e)?;
        let name_offset = u32::from_reader(reader, e)?;
        let name_size = u32::from_reader(reader, e)?;
        let version = u32::from_reader(reader, e)?;
        if version > 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported REL version"));
        }
        let bss_size = u32::from_reader(reader, e)?;
        let rel_offset = u32::from_reader(reader, e)?;
        let imp_offset = u32::from_reader(reader, e)?;
        let imp_size = u32::from_reader(reader, e)?;
        let prolog_section = u8::from_reader(reader, e)?;
        let epilog_section = u8::from_reader(reader, e)?;
        let unresolved_section = u8::from_reader(reader, e)?;
        let bss_section = u8::from_reader(reader, e)?;
        if bss_section != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected bss_section == 0"));
        }
        let prolog_offset = u32::from_reader(reader, e)?;
        let epilog_offset = u32::from_reader(reader, e)?;
        let unresolved_offset = u32::from_reader(reader, e)?;
        let align = if version >= 2 { Some(u32::from_reader(reader, e)?) } else { None };
        let bss_align = if version >= 2 { Some(u32::from_reader(reader, e)?) } else { None };
        let fix_size = if version >= 3 { Some(u32::from_reader(reader, e)?) } else { None };
        Ok(Self {
            module_id,
            num_sections,
            section_info_offset,
            name_offset,
            name_size,
            version,
            bss_size,
            rel_offset,
            imp_offset,
            imp_size,
            prolog_section,
            epilog_section,
            unresolved_section,
            prolog_offset,
            epilog_offset,
            unresolved_offset,
            align,
            bss_align,
            fix_size,
        })
    }
}

impl ToWriter for RelHeader {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.module_id.to_writer(writer, e)?;
        0u32.to_writer(writer, e)?; // next
        0u32.to_writer(writer, e)?; // prev
        self.num_sections.to_writer(writer, e)?;
        self.section_info_offset.to_writer(writer, e)?;
        self.name_offset.to_writer(writer, e)?;
        self.name_size.to_writer(writer, e)?;
        self.version.to_writer(writer, e)?;
        self.bss_size.to_writer(writer, e)?;
        self.rel_offset.to_writer(writer, e)?;
        self.imp_offset.to_writer(writer, e)?;
        self.imp_size.to_writer(writer, e)?;
        self.prolog_section.to_writer(writer, e)?;
        self.epilog_section.to_writer(writer, e)?;
        self.unresolved_section.to_writer(writer, e)?;
        0u8.to_writer(writer, e)?; // bss_section
        self.prolog_offset.to_writer(writer, e)?;
        self.epilog_offset.to_writer(writer, e)?;
        self.unresolved_offset.to_writer(writer, e)?;
        if let Some(align) = self.align {
            align.to_writer(writer, e)?;
        }
        if let Some(bss_align) = self.bss_align {
            bss_align.to_writer(writer, e)?;
        }
        if let Some(fix_size) = self.fix_size {
            fix_size.to_writer(writer, e)?;
        }
        Ok(())
    }

    fn write_size(&self) -> usize {
        const V1_SIZE: usize = struct_size([
            u32::STATIC_SIZE, // module_id
            u32::STATIC_SIZE, // next
            u32::STATIC_SIZE, // prev
            u32::STATIC_SIZE, // num_sections
            u32::STATIC_SIZE, // section_info_offset
            u32::STATIC_SIZE, // name_offset
            u32::STATIC_SIZE, // name_size
            u32::STATIC_SIZE, // version
            u32::STATIC_SIZE, // bss_size
            u32::STATIC_SIZE, // rel_offset
            u32::STATIC_SIZE, // imp_offset
            u32::STATIC_SIZE, // imp_size
            u8::STATIC_SIZE,  // prolog_section
            u8::STATIC_SIZE,  // epilog_section
            u8::STATIC_SIZE,  // unresolved_section
            u8::STATIC_SIZE,  // bss_section
            u32::STATIC_SIZE, // prolog_offset
            u32::STATIC_SIZE, // epilog_offset
            u32::STATIC_SIZE, // unresolved_offset
        ]);
        const V2_SIZE: usize = V1_SIZE
            + struct_size([
                u32::STATIC_SIZE, // align
                u32::STATIC_SIZE, // bss_align
            ]);
        const V3_SIZE: usize = V2_SIZE + u32::STATIC_SIZE; // fix_size
        match self.version {
            1 => V1_SIZE,
            2 => V2_SIZE,
            3 => V3_SIZE,
            _ => panic!("Unsupported REL version {}", self.version),
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct RelImport {
    module_id: u32,
    offset: u32,
}

impl FromReader for RelImport {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // module_id
        u32::STATIC_SIZE, // offset
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self { module_id: u32::from_reader(reader, e)?, offset: u32::from_reader(reader, e)? })
    }
}

impl ToWriter for RelImport {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.module_id.to_writer(writer, e)?;
        self.offset.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

#[derive(Copy, Clone, Debug)]
pub struct RelSectionHeader {
    offset_and_flags: u32,
    size: u32,
}

impl FromReader for RelSectionHeader {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // offset_and_flags
        u32::STATIC_SIZE, // size
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            offset_and_flags: u32::from_reader(reader, e)?,
            size: u32::from_reader(reader, e)?,
        })
    }
}

impl ToWriter for RelSectionHeader {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset_and_flags.to_writer(writer, e)?;
        self.size.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl RelSectionHeader {
    fn new(offset: u32, size: u32, exec: bool) -> Self {
        Self { offset_and_flags: offset | (exec as u32), size }
    }

    pub fn offset(&self) -> u32 { self.offset_and_flags & !1 }

    pub fn size(&self) -> u32 { self.size }

    pub fn exec(&self) -> bool { self.offset_and_flags & 1 != 0 }
}

#[derive(Copy, Clone, Debug)]
struct RelRelocRaw {
    offset: u16,
    kind: u8,
    section: u8,
    addend: u32,
}

impl FromReader for RelRelocRaw {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u16::STATIC_SIZE, // offset
        u8::STATIC_SIZE,  // kind
        u8::STATIC_SIZE,  // section
        u32::STATIC_SIZE, // addend
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            offset: u16::from_reader(reader, e)?,
            kind: u8::from_reader(reader, e)?,
            section: u8::from_reader(reader, e)?,
            addend: u32::from_reader(reader, e)?,
        })
    }
}

impl ToWriter for RelRelocRaw {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset.to_writer(writer, e)?;
        self.kind.to_writer(writer, e)?;
        self.section.to_writer(writer, e)?;
        self.addend.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

pub fn process_rel_header<R>(reader: &mut R) -> Result<RelHeader>
where R: Read + Seek + ?Sized {
    RelHeader::from_reader(reader, Endian::Big).context("Failed to read REL header")
}

pub fn process_rel_sections<R>(
    reader: &mut R,
    header: &RelHeader,
) -> Result<Vec<RelSectionHeader>>
where
    R: Read + Seek + ?Sized,
{
    let mut sections = Vec::with_capacity(header.num_sections as usize);
    reader.seek(SeekFrom::Start(header.section_info_offset as u64))?;
    for idx in 0..header.num_sections {
        let section = RelSectionHeader::from_reader(reader, Endian::Big)
            .with_context(|| format!("Failed to read REL section header {idx}"))?;
        sections.push(section);
    }
    Ok(sections)
}

pub fn process_rel<R>(reader: &mut R, name: &str) -> Result<(RelHeader, ObjInfo)>
where R: Read + Seek + ?Sized {
    let header = process_rel_header(reader)?;
    let mut sections = Vec::with_capacity(header.num_sections as usize);
    let mut text_section = None;
    let mut total_bss_size = 0;
    for (idx, section) in process_rel_sections(reader, &header)?.iter().enumerate() {
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
                format!("Failed to read REL section {idx} data with size {size:#X}")
            })?;
            reader.seek(SeekFrom::Start(position))?;
            data
        };

        let (name, kind, section_known) = if offset == 0 {
            ensure!(total_bss_size == 0, "Multiple BSS sections in REL");
            total_bss_size = size;
            (".bss".to_string(), ObjSectionKind::Bss, true)
        } else if section.exec() {
            ensure!(text_section.is_none(), "Multiple text sections in REL");
            text_section = Some(idx as u8);
            (".text".to_string(), ObjSectionKind::Code, true)
        } else {
            (format!(".section{idx}"), ObjSectionKind::Data, false)
        };
        sections.push(ObjSection {
            name,
            kind,
            address: 0,
            size: size as u64,
            data,
            align: match offset {
                0 => header.bss_align,
                _ => None, // determined later
            }
            .unwrap_or_default() as u64,
            elf_index: idx as SectionIndex,
            relocations: Default::default(),
            virtual_address: None, // TODO option to set?
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
    let mut add_symbol =
        |rel_section_idx: u8, offset: u32, name: &str, force_active: bool| -> Result<()> {
            if rel_section_idx > 0 {
                let (section_index, _) = sections
                    .iter()
                    .enumerate()
                    .find(|&(_, section)| section.elf_index == rel_section_idx as SectionIndex)
                    .ok_or_else(|| anyhow!("Failed to locate {name} section {rel_section_idx}"))?;
                log::debug!("Adding {name} section {rel_section_idx} offset {offset:#X}");
                let mut flags = ObjSymbolFlagSet(ObjSymbolFlags::Global.into());
                if force_active {
                    flags.set_force_active(true);
                }
                symbols.push(ObjSymbol {
                    name: name.to_string(),
                    address: offset as u64,
                    section: Some(section_index as SectionIndex),
                    flags,
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                });
            }
            Ok(())
        };
    add_symbol(header.prolog_section, header.prolog_offset, "_prolog", true)?;
    add_symbol(header.epilog_section, header.epilog_offset, "_epilog", true)?;
    add_symbol(header.unresolved_section, header.unresolved_offset, "_unresolved", true)?;

    let mut unresolved_relocations = Vec::new();
    let mut imp_idx = 0;
    let imp_end = (header.imp_offset + header.imp_size) as u64;
    reader.seek(SeekFrom::Start(header.imp_offset as u64))?;
    while reader.stream_position()? < imp_end {
        let import = RelImport::from_reader(reader, Endian::Big)?;

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
            let reloc = RelRelocRaw::from_reader(reader, Endian::Big)?;
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
                original_section: section,
                original_target_section: reloc.section,
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

pub fn print_relocations<R>(reader: &mut R, header: &RelHeader) -> Result<()>
where R: Read + Seek + ?Sized {
    let imp_end = (header.imp_offset + header.imp_size) as u64;
    reader.seek(SeekFrom::Start(header.imp_offset as u64))?;
    while reader.stream_position()? < imp_end {
        let import = RelImport::from_reader(reader, Endian::Big)?;
        println!("Module {} (file offset {:#X}):", import.module_id, import.offset);

        let position = reader.stream_position()?;
        reader.seek(SeekFrom::Start(import.offset as u64))?;
        let mut address = 0u32;
        let mut section = u8::MAX;
        loop {
            let reloc = RelRelocRaw::from_reader(reader, Endian::Big)?;
            let kind = match reloc.kind as u32 {
                elf::R_PPC_NONE => continue,
                elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 => ObjRelocKind::Absolute,
                elf::R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
                elf::R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
                elf::R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
                elf::R_PPC_REL24 => ObjRelocKind::PpcRel24,
                elf::R_PPC_REL14 => ObjRelocKind::PpcRel14,
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
            println!(
                "    {}:{:#X} {:?} -> {}:{}:{:#X}",
                reloc.section, address, kind, import.module_id, section, reloc.addend
            );
        }
        reader.seek(SeekFrom::Start(position))?;
    }

    Ok(())
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

    // EXTRA for matching
    pub original_section: u8,
    pub original_target_section: u8,
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
    header: &RelHeader,
) -> Result<()> {
    let diff = if rel_reloc.module_id == module_id && rel_reloc.section == rel_reloc.target_section
    {
        rel_reloc.addend as i32 - rel_reloc.address as i32
    } else if header.unresolved_section == rel_reloc.section {
        header.unresolved_offset as i32 - rel_reloc.address as i32
    } else {
        return Ok(());
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
    /// Override individual section alignment in the file.
    pub section_align: Option<Vec<u32>>,
    /// Override individual section executable status in the file.
    /// This is used to match empty sections: mwld will emit them with
    /// NULL type, but the original REL may have them marked executable.
    pub section_exec: Option<Vec<bool>>,
}

pub const PERMITTED_SECTIONS: [&str; 7] =
    [".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss"];

pub fn is_permitted_section(section: &object::Section) -> bool {
    matches!(section.name(), Ok(name) if PERMITTED_SECTIONS.contains(&name))
}

pub fn should_write_section(section: &object::Section) -> bool {
    section.kind() != object::SectionKind::UninitializedData
}

pub fn write_rel<W>(
    w: &mut W,
    info: &RelWriteInfo,
    file: &object::File,
    mut relocations: Vec<RelReloc>,
) -> Result<()>
where
    W: Write + Seek + ?Sized,
{
    if info.version >= 3 {
        // Version 3 RELs put module ID 0 and self-relocations last,
        // so that the space can be reclaimed via OSLinkFixed. (See fix_size)
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
    } else {
        // Version 1 and 2 RELs use simple ascending order.
        relocations.sort_by(|a, b| {
            a.module_id
                .cmp(&b.module_id)
                .then(a.section.cmp(&b.section))
                .then(a.address.cmp(&b.address))
        });
    }

    let mut apply_relocations = vec![];
    relocations.retain(|r| {
        if !is_permitted_section(
            &file.section_by_index(object::SectionIndex(r.original_section as usize)).unwrap(),
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

    /// Get the alignment of a section, checking for overrides.
    /// permitted_section_idx increments whenever a permitted section is encountered,
    /// rather than being the raw ELF section index.
    fn section_align(
        permitted_section_idx: usize,
        section: &object::Section,
        info: &RelWriteInfo,
    ) -> u32 {
        info.section_align
            .as_ref()
            .and_then(|v| v.get(permitted_section_idx))
            .cloned()
            .unwrap_or(section.align() as u32)
            .max(1)
    }

    let mut align = file
        .sections()
        .filter(is_permitted_section)
        .enumerate()
        .map(|(i, s)| section_align(i, &s, info))
        .max()
        .unwrap_or(0);
    let bss = file
        .sections()
        .filter(is_permitted_section)
        .enumerate()
        .find(|(_, s)| s.name() == Ok(".bss"));
    let mut bss_align = bss.as_ref().map(|(i, s)| section_align(*i, s, info)).unwrap_or(1);
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
        section_info_offset: 0, // Calculated below
        name_offset: info.name_offset.unwrap_or(0),
        name_size: info.name_size.unwrap_or(0),
        version: info.version,
        bss_size: bss.as_ref().map(|(_, s)| s.size() as u32).unwrap_or(0),
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
    let mut offset = header.write_size() as u32;
    header.section_info_offset = offset;
    offset += num_sections * RelSectionHeader::STATIC_SIZE as u32;
    let section_data_offset = offset;
    for (idx, section) in file
        .sections()
        .filter(is_permitted_section)
        .enumerate()
        .filter(|(_, s)| should_write_section(s))
    {
        let align = section_align(idx, &section, info) - 1;
        offset = (offset + align) & !align;
        offset += section.size() as u32;
    }
    if info.version >= 3 {
        // Align to 4 after section data
        offset = (offset + 3) & !3;
    }

    fn do_relocation_layout(
        relocations: &[RelReloc],
        header: &mut RelHeader,
        imp_entries: &mut Vec<RelImport>,
        raw_relocations: &mut Vec<RelRelocRaw>,
        offset: &mut u32,
    ) -> Result<()> {
        let mut address = 0u32;
        let mut section = u8::MAX;
        let mut last_module_id = u32::MAX;
        for reloc in relocations {
            if reloc.module_id != last_module_id {
                if last_module_id != u32::MAX {
                    raw_relocations.push(RelRelocRaw {
                        offset: 0,
                        kind: R_DOLPHIN_END as u8,
                        section: 0,
                        addend: 0,
                    });
                    *offset += 8;
                }
                imp_entries.push(RelImport { module_id: reloc.module_id, offset: *offset });
                section = u8::MAX;
                last_module_id = reloc.module_id;
            }
            if header.version >= 3
                && header.fix_size.is_none()
                && (reloc.module_id == 0 || reloc.module_id == header.module_id)
            {
                header.fix_size = Some(*offset);
            }
            if reloc.section != section {
                raw_relocations.push(RelRelocRaw {
                    offset: 0,
                    kind: R_DOLPHIN_SECTION as u8,
                    section: reloc.section,
                    addend: 0,
                });
                *offset += 8;
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
                *offset += 8;
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
            *offset += 8;
        }
        raw_relocations.push(RelRelocRaw {
            offset: 0,
            kind: R_DOLPHIN_END as u8,
            section: 0,
            addend: 0,
        });
        *offset += 8;
        Ok(())
    }

    let imp_count = relocations.iter().map(|r| r.module_id).dedup().count();
    let mut imp_entries = Vec::<RelImport>::with_capacity(imp_count);
    let mut raw_relocations = vec![];
    if !relocations.is_empty() {
        if info.version < 3 {
            // Version 1 and 2 RELs write relocations before the import table.
            header.rel_offset = offset;
            do_relocation_layout(
                &relocations,
                &mut header,
                &mut imp_entries,
                &mut raw_relocations,
                &mut offset,
            )?;
        }
        header.imp_offset = offset;
        header.imp_size = imp_count as u32 * RelImport::STATIC_SIZE as u32;
        offset += header.imp_size;
        if info.version >= 3 {
            // Version 3 RELs write relocations after the import table,
            // so that the import table isn't clobbered by OSLinkFixed.
            header.rel_offset = offset;
            do_relocation_layout(
                &relocations,
                &mut header,
                &mut imp_entries,
                &mut raw_relocations,
                &mut offset,
            )?;
        }
    } else if info.version >= 3 {
        // If we don't have relocations, still set fix_size.
        header.fix_size = Some(offset);
    }

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

    header.to_writer(w, Endian::Big)?;
    ensure!(w.stream_position()? as u32 == header.section_info_offset);
    let mut current_data_offset = section_data_offset;
    let mut permitted_section_idx = 0;
    for section_index in 0..num_sections {
        let Ok(section) = file.section_by_index(object::SectionIndex(section_index as usize))
        else {
            RelSectionHeader::new(0, 0, false).to_writer(w, Endian::Big)?;
            continue;
        };
        if is_permitted_section(&section) {
            let mut offset = 0;
            if should_write_section(&section) {
                let align = section_align(permitted_section_idx, &section, info) - 1;
                current_data_offset = (current_data_offset + align) & !align;
                offset = current_data_offset;
                current_data_offset += section.size() as u32;
            }
            let exec = info
                .section_exec
                .as_ref()
                .and_then(|m| m.get(section_index as usize).copied())
                .unwrap_or(section.kind() == object::SectionKind::Text);
            RelSectionHeader::new(offset, section.size() as u32, exec).to_writer(w, Endian::Big)?;
            permitted_section_idx += 1;
        } else {
            RelSectionHeader::new(0, 0, false).to_writer(w, Endian::Big)?;
        }
    }
    ensure!(w.stream_position()? as u32 == section_data_offset);
    fn calculate_padding(position: u64, align: u64) -> u64 {
        let align = align - 1;
        ((position + align) & !align) - position
    }
    for (idx, section) in file
        .sections()
        .filter(is_permitted_section)
        .enumerate()
        .filter(|(_, s)| should_write_section(s))
    {
        let position = w.stream_position()?;
        let align = section_align(idx, &section, info);
        w.write_all(&vec![0u8; calculate_padding(position, align as u64) as usize])?;

        let section_index = section.index().0 as u8;
        let mut section_data = section.uncompressed_data()?;
        if apply_relocations.iter().any(|r| r.original_section == section_index) {
            let mut data = section_data.into_owned();
            for reloc in apply_relocations.iter().filter(|r| r.original_section == section_index) {
                apply_relocation(&mut data, info.module_id, reloc, &header)?;
            }
            section_data = data.into_cow();
        }
        w.write_all(&section_data)?;
    }
    if info.version >= 3 {
        // Align to 4 after section data
        let position = w.stream_position()?;
        w.write_all(&vec![0u8; calculate_padding(position, 4) as usize])?;
    }
    if !relocations.is_empty() {
        if info.version < 3 {
            // Version 1 and 2 RELs write relocations before the import table.
            ensure!(w.stream_position()? as u32 == header.rel_offset);
            for reloc in &raw_relocations {
                reloc.to_writer(w, Endian::Big)?;
            }
        }
        ensure!(w.stream_position()? as u32 == header.imp_offset);
        for entry in &imp_entries {
            entry.to_writer(w, Endian::Big)?;
        }
        if info.version >= 3 {
            // Version 3 RELs write relocations after the import table. See above.
            ensure!(w.stream_position()? as u32 == header.rel_offset);
            for reloc in &raw_relocations {
                reloc.to_writer(w, Endian::Big)?;
            }
        }
    }
    ensure!(w.stream_position()? as u32 == offset);
    Ok(())
}

/// Determines REL section alignment based on its file offset.
pub fn update_rel_section_alignment(obj: &mut ObjInfo, header: &RelHeader) -> Result<()> {
    let mut last_offset = header.section_info_offset + header.num_sections * 8;
    for (_, section) in obj.sections.iter_mut() {
        let prev_offset = last_offset;
        last_offset = (section.file_offset + section.size) as u32;

        if section.align > 0 {
            // Already set
            continue;
        }

        if section.section_known {
            // Try the default section alignment for known sections
            let default_align = default_section_align(section);
            if align_up(prev_offset, default_align as u32) == section.file_offset as u32 {
                section.align = default_align;
                continue;
            }
        }

        // Work our way down from the REL header alignment
        let mut align = header.align.unwrap_or(32);
        while align >= 4 {
            if align_up(prev_offset, align) == section.file_offset as u32 {
                section.align = align as u64;
                break;
            }
            align /= 2;
        }

        if section.align == 0 {
            bail!(
                "Failed to determine alignment for REL section {}: {:#X} -> {:#X}",
                section.name,
                prev_offset,
                section.file_offset
            );
        }
    }
    Ok(())
}
