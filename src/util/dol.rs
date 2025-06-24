use std::{
    collections::BTreeMap,
    io,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use itertools::Itertools;

use crate::{
    analysis::cfa::{
        locate_bss_memsets, locate_cross_section_branch_targets, locate_sda_bases, SectionAddress,
    },
    array_ref,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
    util::{
        alf::{AlfFile, AlfSymbol, ALF_MAGIC},
        align_up,
        reader::{skip_bytes, Endian, FromReader, ToWriter},
    },
};

const MAX_TEXT_SECTIONS: usize = 7;
const MAX_DATA_SECTIONS: usize = 11;
const MAX_ROM_COPY_INFO_SIZE: usize = (MAX_TEXT_SECTIONS + MAX_DATA_SECTIONS + 1) * 3 * 4; // num sections * 3 entries * u32
const MAX_BSS_INIT_INFO_SIZE: usize = (MAX_DATA_SECTIONS + 1) * 2 * 4; // num sections * 2 entries * u32
const ETI_INIT_INFO_SIZE: usize = 16; // eti_start, eti_end, code_start, code_size

/// Unified trait for DOL and ALF files
pub trait DolLike {
    fn sections(&self) -> &[DolSection];

    fn symbols(&self) -> &[AlfSymbol] { &[] }

    fn entry_point(&self) -> u32;

    fn has_unified_bss(&self) -> bool;

    fn section_by_address(&self, addr: u32) -> Option<&DolSection> {
        self.sections()
            .iter()
            .find(|section| addr >= section.address && addr < section.address + section.size)
    }

    fn virtual_data_at<'a>(&self, buf: &'a [u8], addr: u32, size: u32) -> Result<&'a [u8]> {
        let section = self
            .section_by_address(addr)
            .ok_or_else(|| anyhow!("Failed to locate section for address {:#010X}", addr))?;
        let offset = addr - section.address;
        ensure!(
            offset + size <= section.size,
            "Invalid virtual data range {:#010X}-{:#010X} (section: {:#010X}-{:#010X})",
            addr,
            addr + size,
            section.address,
            section.address + section.size
        );
        let offset = section.file_offset as usize + offset as usize;
        Ok(&buf[offset..offset + size as usize])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DolSectionKind {
    Text,
    Data,
    Bss,
}

#[derive(Debug, Clone)]
pub struct DolSection {
    pub address: u32,
    pub file_offset: u32,
    pub data_size: u32,
    pub size: u32,
    pub kind: DolSectionKind,
    // TODO remove
    pub index: SectionIndex,
}

#[derive(Debug, Clone)]
pub struct DolFile {
    pub header: DolHeader,
    pub sections: Vec<DolSection>,
}

impl FromReader for DolFile {
    type Args = ();

    const STATIC_SIZE: usize = DolHeader::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let header = DolHeader::from_reader(reader, e)?;
        let mut sections = Vec::with_capacity(header.text_sizes.len() + header.data_sizes.len());
        for (idx, &size) in header.text_sizes.iter().enumerate() {
            if size == 0 {
                continue;
            }
            sections.push(DolSection {
                address: header.text_addrs[idx],
                file_offset: header.text_offs[idx],
                data_size: size,
                size,
                kind: DolSectionKind::Text,
                index: sections.len() as SectionIndex,
            });
        }
        for (idx, &size) in header.data_sizes.iter().enumerate() {
            if size == 0 {
                continue;
            }
            sections.push(DolSection {
                address: header.data_addrs[idx],
                file_offset: header.data_offs[idx],
                data_size: size,
                size,
                kind: DolSectionKind::Data,
                index: sections.len() as SectionIndex,
            });
        }
        sections.push(DolSection {
            address: header.bss_addr,
            file_offset: 0,
            data_size: 0,
            size: header.bss_size,
            kind: DolSectionKind::Bss,
            index: sections.len() as SectionIndex,
        });
        Ok(Self { header, sections })
    }
}

#[derive(Debug, Clone, Default)]
pub struct DolHeader {
    pub text_offs: [u32; MAX_TEXT_SECTIONS],
    pub data_offs: [u32; MAX_DATA_SECTIONS],
    pub text_addrs: [u32; MAX_TEXT_SECTIONS],
    pub data_addrs: [u32; MAX_DATA_SECTIONS],
    pub text_sizes: [u32; MAX_TEXT_SECTIONS],
    pub data_sizes: [u32; MAX_DATA_SECTIONS],
    pub bss_addr: u32,
    pub bss_size: u32,
    pub entry_point: u32,
}

impl FromReader for DolHeader {
    type Args = ();

    const STATIC_SIZE: usize = 0x100;

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let result = Self {
            text_offs: <_>::from_reader(reader, e)?,
            data_offs: <_>::from_reader(reader, e)?,
            text_addrs: <_>::from_reader(reader, e)?,
            data_addrs: <_>::from_reader(reader, e)?,
            text_sizes: <_>::from_reader(reader, e)?,
            data_sizes: <_>::from_reader(reader, e)?,
            bss_addr: <_>::from_reader(reader, e)?,
            bss_size: <_>::from_reader(reader, e)?,
            entry_point: <_>::from_reader(reader, e)?,
        };
        skip_bytes::<0x1C, _>(reader)?; // padding
        Ok(result)
    }
}

impl ToWriter for DolHeader {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.text_offs.to_writer(writer, e)?;
        self.data_offs.to_writer(writer, e)?;
        self.text_addrs.to_writer(writer, e)?;
        self.data_addrs.to_writer(writer, e)?;
        self.text_sizes.to_writer(writer, e)?;
        self.data_sizes.to_writer(writer, e)?;
        self.bss_addr.to_writer(writer, e)?;
        self.bss_size.to_writer(writer, e)?;
        self.entry_point.to_writer(writer, e)?;
        // padding
        for _ in 0..0x1C {
            writer.write_all(&[0])?;
        }
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl DolLike for DolFile {
    fn sections(&self) -> &[DolSection] { &self.sections }

    fn entry_point(&self) -> u32 { self.header.entry_point }

    fn has_unified_bss(&self) -> bool { true }
}

fn read_u32(buf: &[u8], dol: &dyn DolLike, addr: u32) -> Result<u32> {
    Ok(u32::from_be_bytes(dol.virtual_data_at(buf, addr, 4)?.try_into()?))
}

pub fn process_dol(buf: &[u8], name: &str) -> Result<ObjInfo> {
    let mut reader = Cursor::new(buf);
    let dol: Box<dyn DolLike> = if buf.len() > 4 && *array_ref!(buf, 0, 4) == ALF_MAGIC {
        Box::new(AlfFile::from_reader(&mut reader, Endian::Little)?)
    } else {
        Box::new(DolFile::from_reader(&mut reader, Endian::Big)?)
    };

    let mut entry_point = dol.entry_point();
    let mut is_bootstage = false;
    if entry_point & 0x80000000 == 0 {
        entry_point |= 0x80000000;
        is_bootstage = true;
    }

    // Locate _rom_copy_info
    let first_rom_section = dol
        .sections()
        .iter()
        .find(|section| section.kind != DolSectionKind::Bss)
        .ok_or_else(|| anyhow!("Failed to locate first rom section"))?;
    let init_section = dol
        .section_by_address(entry_point)
        .ok_or_else(|| anyhow!("Failed to locate .init section"))?;
    let first_data_section = dol
        .sections()
        .iter()
        .find(|s| s.kind == DolSectionKind::Data)
        .ok_or_else(|| anyhow!("Failed to locate .data section"))?;
    let rom_copy_section = if is_bootstage { first_data_section } else { init_section };

    if is_bootstage {
        // Real entry point is stored at the end of the bootstage init section, always(?) 0x81330000
        entry_point = read_u32(buf, dol.as_ref(), init_section.address + init_section.size - 4)?;
    }

    let rom_copy_info_addr = {
        let mut addr = if is_bootstage {
            // Start searching from the beginning of the BootStage "data" section
            rom_copy_section.address
        } else {
            // Start searching from the end of the .init section
            rom_copy_section.address + rom_copy_section.size
                - MAX_ROM_COPY_INFO_SIZE as u32
                - MAX_BSS_INIT_INFO_SIZE as u32
        };
        loop {
            let value = read_u32(buf, dol.as_ref(), addr)?;
            if value == first_rom_section.address || value == entry_point {
                log::debug!("Found _rom_copy_info @ {addr:#010X}");
                break Some(addr);
            }
            addr += 4;
            if addr >= rom_copy_section.address + rom_copy_section.size {
                log::warn!("Failed to locate _rom_copy_info");
                break None;
            }
        }
    };

    // Process _rom_copy_info
    let mut rom_sections = BTreeMap::<u32, u32>::new();
    let rom_copy_info_end = match rom_copy_info_addr {
        Some(mut addr) => loop {
            let rom = read_u32(buf, dol.as_ref(), addr)?;
            let copy = read_u32(buf, dol.as_ref(), addr + 4)?;
            ensure!(
                rom == copy,
                "Unsupported section: ROM address {rom:#010X} != copy address {copy:#010X}",
            );
            let size = read_u32(buf, dol.as_ref(), addr + 8)?;
            addr += 12;
            if size == 0 {
                log::debug!("Found _rom_copy_info end @ {addr:#010X}");
                break Some(addr);
            }
            if addr >= rom_copy_section.address + rom_copy_section.size {
                log::warn!("Failed to locate _rom_copy_info end");
                break None;
            }
            rom_sections.insert(rom, size);
        },
        None => None,
    };

    // Locate _bss_init_info
    let bss_section = dol
        .sections()
        .iter()
        .find(|section| section.kind == DolSectionKind::Bss)
        .ok_or_else(|| anyhow!("Failed to locate BSS section"))?;
    let bss_init_info_addr = match rom_copy_info_end {
        Some(mut addr) => loop {
            let value = read_u32(buf, dol.as_ref(), addr)?;
            if is_bootstage
                || (value >= bss_section.address && value < bss_section.address + bss_section.size)
            {
                log::debug!("Found _bss_init_info @ {addr:#010X}");
                break Some(addr);
            }
            addr += 4;
            if addr >= rom_copy_section.address + rom_copy_section.size {
                log::warn!("Failed to locate _bss_init_info");
                break None;
            }
        },
        None => None,
    };

    // Process _bss_init_info
    let mut bss_sections = BTreeMap::<u32, u32>::new();
    let bss_init_info_end = match bss_init_info_addr {
        Some(mut addr) => loop {
            let rom = read_u32(buf, dol.as_ref(), addr)?;
            let size = read_u32(buf, dol.as_ref(), addr + 4)?;
            addr += 8;
            if size == 0 {
                log::debug!("Found _bss_init_info end @ {addr:#010X}");
                break Some(addr);
            }
            if addr >= rom_copy_section.address + rom_copy_section.size {
                log::warn!("Failed to locate _bss_init_info end");
                break None;
            }
            bss_sections.insert(rom, size);
        },
        None => None,
    };

    // Add text and data sections
    let mut sections = vec![];
    if is_bootstage {
        // Create sections based on _rom_copy_info
        for (idx, (&addr, &size)) in rom_sections.iter().enumerate() {
            let dol_section = dol
                .section_by_address(addr)
                .ok_or_else(|| anyhow!("Failed to locate section for ROM address {addr:#010X}"))?;
            let data = dol.virtual_data_at(buf, addr, size)?;

            let (name, kind, known) = if entry_point >= addr && entry_point < addr + size {
                (".init".to_string(), ObjSectionKind::Code, true)
            } else {
                match dol_section.kind {
                    DolSectionKind::Text => (format!(".text{idx}"), ObjSectionKind::Code, false),
                    DolSectionKind::Data => (format!(".data{idx}"), ObjSectionKind::Data, false),
                    DolSectionKind::Bss => (format!(".bss{idx}"), ObjSectionKind::Bss, false),
                }
            };

            let file_offset = addr - dol_section.address + dol_section.file_offset;
            sections.push(ObjSection {
                name,
                kind,
                address: addr as u64,
                size: size as u64,
                data: data.to_vec(),
                align: 0,
                elf_index: 0,
                relocations: Default::default(),
                virtual_address: Some(addr as u64),
                file_offset: file_offset as u64,
                section_known: known,
                splits: Default::default(),
            });
        }
    } else {
        for dol_section in dol.sections().iter() {
            // We'll split .bss later
            if dol_section.kind == DolSectionKind::Bss && dol.has_unified_bss() {
                continue;
            }

            let (name, kind, known) = match dol_section.index {
                idx if idx == init_section.index => {
                    (".init".to_string(), ObjSectionKind::Code, true)
                }
                idx => match dol_section.kind {
                    DolSectionKind::Text => (format!(".text{idx}"), ObjSectionKind::Code, false),
                    DolSectionKind::Data => (format!(".data{idx}"), ObjSectionKind::Data, false),
                    DolSectionKind::Bss => (format!(".bss{idx}"), ObjSectionKind::Bss, false),
                },
            };

            let (size, data): (u32, &[u8]) = if kind == ObjSectionKind::Bss {
                (dol_section.size, &[])
            } else {
                // Use section size from _rom_copy_info
                let size = match rom_sections.get(&dol_section.address) {
                    Some(&size) => size,
                    None => {
                        if !rom_sections.is_empty() {
                            log::warn!(
                                "Section {} ({:#010X}) doesn't exist in _rom_copy_info",
                                dol_section.index,
                                dol_section.address
                            );
                        }
                        dol_section.size
                    }
                };
                (size, dol.virtual_data_at(buf, dol_section.address, size)?)
            };

            sections.push(ObjSection {
                name,
                kind,
                address: dol_section.address as u64,
                size: size as u64,
                data: data.to_vec(),
                align: 0,
                elf_index: 0,
                relocations: Default::default(),
                virtual_address: Some(dol_section.address as u64),
                file_offset: dol_section.file_offset as u64,
                section_known: known,
                splits: Default::default(),
            });
        }
    }

    if dol.has_unified_bss() {
        // Add BSS sections from _bss_init_info
        for (idx, (&addr, &size)) in bss_sections.iter().enumerate() {
            ensure!(
                is_bootstage
                    || (addr >= bss_section.address
                        && addr < bss_section.address + bss_section.size
                        && addr + size <= bss_section.address + bss_section.size),
                "Invalid BSS range {:#010X}-{:#010X} (DOL BSS: {:#010X}-{:#010X})",
                addr,
                addr + size,
                bss_section.address,
                bss_section.address + bss_section.size
            );

            sections.push(ObjSection {
                name: format!(".bss{idx}"),
                kind: ObjSectionKind::Bss,
                address: addr as u64,
                size: size as u64,
                data: vec![],
                align: 0,
                elf_index: 0,
                relocations: Default::default(),
                virtual_address: Some(addr as u64),
                file_offset: 0,
                section_known: false,
                splits: Default::default(),
            });
        }

        // ProDG: Locate BSS sections by analyzing the entry point
        if bss_sections.is_empty() {
            // Create temporary object
            let mut temp_sections = sections.clone();
            temp_sections.push(ObjSection {
                name: ".bss".to_string(),
                kind: ObjSectionKind::Bss,
                address: bss_section.address as u64,
                size: bss_section.size as u64,
                data: vec![],
                align: 0,
                elf_index: 0,
                relocations: Default::default(),
                virtual_address: Some(bss_section.address as u64),
                file_offset: 0,
                section_known: false,
                splits: Default::default(),
            });
            let mut obj = ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                name.to_string(),
                vec![],
                temp_sections,
            );
            obj.entry = Some(entry_point as u64);
            let bss_sections = locate_bss_memsets(&obj)?;
            match bss_sections.len() {
                0 => log::warn!("Failed to locate BSS sections"),
                2 => {
                    // .bss and .sbss
                    sections.push(ObjSection {
                        name: ".bss".to_string(),
                        kind: ObjSectionKind::Bss,
                        address: bss_sections[0].0 as u64,
                        size: bss_sections[0].1 as u64,
                        data: vec![],
                        align: 0,
                        elf_index: 0,
                        relocations: Default::default(),
                        virtual_address: Some(bss_sections[0].0 as u64),
                        file_offset: 0,
                        section_known: false,
                        splits: Default::default(),
                    });
                    sections.push(ObjSection {
                        name: ".sbss".to_string(),
                        kind: ObjSectionKind::Bss,
                        address: bss_sections[1].0 as u64,
                        size: bss_sections[1].1 as u64,
                        data: vec![],
                        align: 0,
                        elf_index: 0,
                        relocations: Default::default(),
                        virtual_address: Some(bss_sections[1].0 as u64),
                        file_offset: 0,
                        section_known: false,
                        splits: Default::default(),
                    });
                }
                n => bail!("Invalid number of BSS sections: {}", n),
            }
        }

        // Sort sections by address ascending
        sections.sort_by_key(|s| s.address);
    }

    // Apply section indices
    for (idx, section) in sections.iter_mut().enumerate() {
        // Assume the original ELF section index is +1
        // ELF files start with a NULL section
        section.elf_index = (idx as SectionIndex) + 1;
    }

    // Guess section alignment
    let mut last_section_end = sections.first().map_or(0, |s| s.address as u32);
    for section in &mut sections {
        let section_start = section.address as u32;
        let mut align = 4;
        while align_up(last_section_end, align) < section_start {
            align = (align + 1).next_power_of_two();
        }
        if align_up(last_section_end, align) != section_start {
            log::warn!(
                "Couldn't determine alignment for section '{}' ({:#010X} -> {:#010X})",
                section.name,
                last_section_end,
                section_start
            );
            align = 32;
        }
        last_section_end = section_start + section.size as u32;
        section.align = align as u64;
    }

    // Create object
    let mut obj = ObjInfo::new(
        ObjKind::Executable,
        ObjArchitecture::PowerPc,
        name.to_string(),
        vec![],
        sections,
    );
    obj.entry = Some(entry_point as u64);

    // Generate _rom_copy_info symbol
    if let (Some(rom_copy_info_addr), Some(rom_copy_info_end)) =
        (rom_copy_info_addr, rom_copy_info_end)
    {
        let (section_index, _) = obj.sections.at_address(rom_copy_info_addr)?;
        obj.add_symbol(
            ObjSymbol {
                name: "_rom_copy_info".to_string(),
                address: rom_copy_info_addr as u64,
                section: Some(section_index),
                size: (rom_copy_info_end - rom_copy_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            true,
        )?;
    }

    // Generate _bss_init_info symbol
    if let (Some(bss_init_info_addr), Some(bss_init_info_end)) =
        (bss_init_info_addr, bss_init_info_end)
    {
        let (section_index, _) = obj.sections.at_address(bss_init_info_addr)?;
        obj.add_symbol(
            ObjSymbol {
                name: "_bss_init_info".to_string(),
                address: bss_init_info_addr as u64,
                section: Some(section_index),
                size: (bss_init_info_end - bss_init_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            true,
        )?;
    }

    // Locate .text section
    if let Err(e) = locate_text(&mut obj) {
        log::warn!("Failed to locate .text section: {:?}", e);
    }

    // Locate extab and extabindex sections
    if let Err(e) = locate_extab_extabindex(&mut obj) {
        log::warn!("Failed to locate extab/etabindex: {:?}", e);
    }

    // Locate .ctors and .dtors sections
    if let Err(e) = locate_ctors_dtors(&mut obj) {
        log::warn!("Failed to locate .ctors/.dtors: {:?}", e);
    }

    // Locate _SDA2_BASE_ & _SDA_BASE_
    match locate_sda_bases(&mut obj) {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("Unable to locate SDA bases");
        }
        Err(e) => {
            log::warn!("Failed to locate SDA bases: {:?}", e);
        }
    }

    // Apply ALF symbols
    for symbol in dol.symbols() {
        obj.add_symbol(symbol.to_obj_symbol()?, true)?;
    }

    Ok(obj)
}

#[derive(Debug, Clone)]
struct EtiInitInfo {
    eti_start: u32,
    eti_end: u32,
    code_start: u32,
    code_size: u32,
}

impl EtiInitInfo {
    #[inline]
    fn is_zero(&self) -> bool {
        self.eti_start == 0 && self.eti_end == 0 && self.code_start == 0 && self.code_size == 0
    }
}

#[derive(Debug, Clone)]
struct EtiEntry {
    address: u32,
    function: u32,
    function_size: u32,
    extab_addr: u32,
}

fn read_u32_obj(obj: &ObjInfo, addr: u32) -> Result<u32> {
    let (_, section) = obj.sections.at_address(addr)?;
    let data = section.data_range(addr, addr + 4)?;
    Ok(u32::from_be_bytes(data.try_into()?))
}

fn read_eti_init_info(obj: &ObjInfo, addr: u32) -> Result<EtiInitInfo> {
    let eti_start = read_u32_obj(obj, addr)?;
    let eti_end = read_u32_obj(obj, addr + 4)?;
    let code_start = read_u32_obj(obj, addr + 8)?;
    let code_size = read_u32_obj(obj, addr + 12)?;
    Ok(EtiInitInfo { eti_start, eti_end, code_start, code_size })
}

fn read_eti_entry(obj: &ObjInfo, address: u32) -> Result<EtiEntry> {
    let function = read_u32_obj(obj, address)?;
    let function_size = read_u32_obj(obj, address + 4)?;
    let extab_addr = read_u32_obj(obj, address + 8)?;
    Ok(EtiEntry { address, function, function_size, extab_addr })
}

fn validate_eti_init_info(
    obj: &ObjInfo,
    eti_init_info: &EtiInitInfo,
    eti_section_addr: u32,
    eti_section_end: u32,
) -> Result<bool> {
    if eti_init_info.eti_start >= eti_section_addr
        && eti_init_info.eti_start < eti_section_end
        && eti_init_info.eti_end >= eti_section_addr
        && eti_init_info.eti_end < eti_section_end
    {
        if let Ok((_, code_section)) = obj.sections.at_address(eti_init_info.code_start) {
            if eti_init_info.code_start + eti_init_info.code_size
                <= (code_section.address + code_section.size) as u32
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn write_dol<W>(obj: &ObjInfo, out: &mut W) -> Result<()>
where W: Write + Seek + ?Sized {
    let mut header = DolHeader { entry_point: obj.entry.unwrap() as u32, ..Default::default() };
    let mut offset = 0x100u32;
    out.seek(SeekFrom::Start(offset as u64))?;

    // Text sections
    for (num_sections, (_, section)) in
        obj.sections.iter().filter(|(_, s)| s.kind == ObjSectionKind::Code).enumerate()
    {
        log::debug!("Processing text section '{}'", section.name);
        let size = align32(section.size as u32);
        if num_sections >= MAX_TEXT_SECTIONS {
            bail!("Too many text sections (while processing '{}')", section.name);
        }
        header.text_offs[num_sections] = offset;
        header.text_addrs[num_sections] = section.address as u32;
        header.text_sizes[num_sections] = size;
        write_aligned(out, &section.data, size)?;
        offset += size;
    }

    // Data sections
    for (num_sections, (_, section)) in obj
        .sections
        .iter()
        .filter(|(_, s)| matches!(s.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData))
        .enumerate()
    {
        log::debug!("Processing data section '{}'", section.name);
        let size = align32(section.size as u32);
        if num_sections >= MAX_DATA_SECTIONS {
            bail!("Too many data sections (while processing '{}')", section.name);
        }
        header.data_offs[num_sections] = offset;
        header.data_addrs[num_sections] = section.address as u32;
        header.data_sizes[num_sections] = size;
        write_aligned(out, &section.data, size)?;
        offset += size;
    }

    // BSS sections
    for (_, section) in obj.sections.iter().filter(|(_, s)| s.kind == ObjSectionKind::Bss) {
        let address = section.address as u32;
        let size = section.size as u32;
        if header.bss_addr == 0 {
            header.bss_addr = address;
        }
        header.bss_size = (address + size) - header.bss_addr;
    }

    // Header
    out.rewind()?;
    header.to_writer(out, Endian::Big)?;

    // Done!
    out.flush()?;
    Ok(())
}

#[inline]
const fn align32(x: u32) -> u32 { (x + 31) & !31 }

const ZERO_BUF: [u8; 32] = [0u8; 32];

#[inline]
fn write_aligned<T>(out: &mut T, bytes: &[u8], aligned_size: u32) -> std::io::Result<()>
where T: Write + ?Sized {
    out.write_all(bytes)?;
    let padding = aligned_size - bytes.len() as u32;
    if padding > 0 {
        out.write_all(&ZERO_BUF[0..padding as usize])?;
    }
    Ok(())
}

fn rename_section(
    obj: &mut ObjInfo,
    index: SectionIndex,
    name: &str,
    kind: ObjSectionKind,
) -> Result<()> {
    let section = &mut obj.sections[index];
    ensure!(
        !section.section_known,
        "Section {} is already known, cannot rename to {}",
        section.name,
        name
    );
    section.name = name.to_string();
    section.kind = kind;
    section.section_known = true;
    Ok(())
}

fn locate_text(obj: &mut ObjInfo) -> Result<()> {
    // If we didn't find .text, infer from branch targets from .init section
    if !obj.sections.iter().any(|(_, s)| s.section_known && s.name == ".text") {
        let entry_point = obj.entry.ok_or_else(|| anyhow!("Missing entry point"))? as u32;
        let (entry_section_index, _) = obj.sections.at_address(entry_point)?;
        let entry = SectionAddress::new(entry_section_index, entry_point);
        let branch_targets = locate_cross_section_branch_targets(obj, entry)?;
        let mut section_indexes = branch_targets.iter().map(|s| s.section).dedup();
        let text_section_index =
            section_indexes.next().ok_or_else(|| anyhow!("Failed to locate .text section"))?;
        ensure!(section_indexes.next().is_none(), "Multiple possible .text sections found");
        rename_section(obj, text_section_index, ".text", ObjSectionKind::Code)?;
    }
    Ok(())
}

fn locate_ctors_dtors(obj: &mut ObjInfo) -> Result<()> {
    // Add .ctors and .dtors functions to known functions if they exist
    let mut ctors_section_index = None;
    let mut dtors_section_index = None;
    for (section_index, section) in obj.sections.iter() {
        if section.size & 3 != 0 {
            continue;
        }
        let mut entries = vec![];
        let mut current_addr = section.address as u32;
        for chunk in section.data.chunks_exact(4) {
            let addr = u32::from_be_bytes(chunk.try_into()?);
            if addr == 0 || addr & 3 != 0 {
                break;
            }
            let Ok((section_index, section)) = obj.sections.at_address(addr) else {
                break;
            };
            if section.kind != ObjSectionKind::Code {
                break;
            }
            entries.push(SectionAddress::new(section_index, addr));
            current_addr += 4;
        }
        // .ctors and .dtors end with a null pointer
        if current_addr != (section.address + section.size) as u32 - 4
            || section.data_range(current_addr, 0)?.iter().any(|&b| b != 0)
        {
            continue;
        }
        obj.known_functions.extend(entries.into_iter().map(|addr| (addr, None)));
        match (ctors_section_index, dtors_section_index) {
            (None, None) => ctors_section_index = Some(section_index),
            (Some(_), None) => dtors_section_index = Some(section_index),
            _ => log::warn!("Multiple possible .ctors/.dtors sections found"),
        }
    }
    if let Some(ctors_section) = ctors_section_index {
        rename_section(obj, ctors_section, ".ctors", ObjSectionKind::ReadOnlyData)?;
    }
    if let Some(dtors_section) = dtors_section_index {
        rename_section(obj, dtors_section, ".dtors", ObjSectionKind::ReadOnlyData)?;
    }
    Ok(())
}

fn locate_extab_extabindex(obj: &mut ObjInfo) -> Result<()> {
    let num_text_sections =
        obj.sections.iter().filter(|(_, section)| section.kind == ObjSectionKind::Code).count();
    let mut eti_entries: Vec<EtiEntry> = Vec::new();
    let mut eti_init_info_range: Option<(u32, u32)> = None;
    let mut extab_section_index: Option<SectionIndex> = None;
    let mut extabindex_section_index: Option<SectionIndex> = None;
    'outer: for (dol_section_index, dol_section) in
        obj.sections.iter().filter(|(_, section)| section.kind == ObjSectionKind::Data)
    {
        let dol_section_start = dol_section.address as u32;
        let dol_section_end = dol_section_start + dol_section.size as u32;
        let eti_init_info_addr = {
            let mut addr = dol_section_end - (ETI_INIT_INFO_SIZE * (num_text_sections + 1)) as u32;
            loop {
                let eti_init_info = read_eti_init_info(obj, addr)?;
                if validate_eti_init_info(obj, &eti_init_info, dol_section_start, dol_section_end)?
                {
                    log::debug!("Found _eti_init_info @ {addr:#010X}");
                    break addr;
                }
                addr += 4;
                if addr > dol_section_end - ETI_INIT_INFO_SIZE as u32 {
                    continue 'outer;
                }
            }
        };

        let eti_init_info_end = {
            let mut addr = eti_init_info_addr;
            loop {
                let eti_init_info = read_eti_init_info(obj, addr)?;
                addr += 16;
                if eti_init_info.is_zero() {
                    break;
                }
                if addr > dol_section_end - ETI_INIT_INFO_SIZE as u32 {
                    bail!(
                        "Failed to locate _eti_init_info end (start @ {:#010X})",
                        eti_init_info_addr
                    );
                }
                if !validate_eti_init_info(obj, &eti_init_info, dol_section_start, dol_section_end)?
                {
                    bail!("Invalid _eti_init_info entry: {:#010X?}", eti_init_info);
                }
                for addr in (eti_init_info.eti_start..eti_init_info.eti_end).step_by(12) {
                    let eti_entry = read_eti_entry(obj, addr)?;
                    let (entry_section_index, _) =
                        obj.sections.at_address(eti_entry.extab_addr).with_context(|| {
                            format!(
                                "Failed to locate section for extab address {:#010X}",
                                eti_entry.extab_addr
                            )
                        })?;
                    if let Some(extab_section) = extab_section_index {
                        ensure!(
                            entry_section_index == extab_section,
                            "Mismatched sections for extabindex entries: {} != {}",
                            entry_section_index,
                            extab_section
                        );
                    } else {
                        extab_section_index = Some(entry_section_index);
                    }
                    eti_entries.push(eti_entry);
                }
            }
            log::debug!("Found _eti_init_info end @ {addr:#010X}");
            addr
        };

        eti_init_info_range = Some((eti_init_info_addr, eti_init_info_end));
        extabindex_section_index = Some(dol_section_index);
        break;
    }
    if eti_init_info_range.is_none() {
        log::debug!("Failed to locate _eti_init_info");
    }
    if let Some(extab_section_index) = extab_section_index {
        rename_section(obj, extab_section_index, "extab", ObjSectionKind::ReadOnlyData)?;
    }
    if let Some(extabindex_section_index) = extabindex_section_index {
        rename_section(obj, extabindex_section_index, "extabindex", ObjSectionKind::ReadOnlyData)?;
    }

    // Generate _eti_init_info symbol
    if let Some((eti_init_info_addr, eti_init_info_end)) = eti_init_info_range {
        obj.add_symbol(
            ObjSymbol {
                name: "_eti_init_info".to_string(),
                address: eti_init_info_addr as u64,
                section: extabindex_section_index,
                size: (eti_init_info_end - eti_init_info_addr) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            true,
        )?;
    }

    // Generate symbols for extab & extabindex entries
    if let (Some(extabindex_section_index), Some(extab_section_index)) =
        (extabindex_section_index, extab_section_index)
    {
        let extab_section = &obj.sections[extab_section_index];
        let extab_section_address = extab_section.address;
        let extab_section_size = extab_section.size;

        for entry in &eti_entries {
            // Add functions from extabindex entries as known function bounds
            let (section_index, _) = obj.sections.at_address(entry.function).map_err(|_| {
                anyhow!(
                    "Failed to locate section for function {:#010X} (referenced from extabindex entry {:#010X})",
                    entry.function,
                    entry.address,
                )
            })?;
            let addr = SectionAddress::new(section_index, entry.function);
            if let Some(Some(old_value)) =
                obj.known_functions.insert(addr, Some(entry.function_size))
            {
                if old_value != entry.function_size {
                    log::warn!(
                        "Conflicting sizes for {:#010X}: {:#X} != {:#X}",
                        entry.function,
                        entry.function_size,
                        old_value
                    );
                }
            }
            obj.add_symbol(
                ObjSymbol {
                    name: format!("@eti_{:08X}", entry.address),
                    address: entry.address as u64,
                    section: Some(extabindex_section_index),
                    size: 12,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local | ObjSymbolFlags::Hidden),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                false,
            )?;
        }

        let mut entry_iter = eti_entries.iter().peekable();
        loop {
            let (addr, size) = match (entry_iter.next(), entry_iter.peek()) {
                (Some(a), Some(&b)) => (a.extab_addr, b.extab_addr - a.extab_addr),
                (Some(a), None) => (
                    a.extab_addr,
                    (extab_section_address + extab_section_size) as u32 - a.extab_addr,
                ),
                _ => break,
            };
            obj.add_symbol(
                ObjSymbol {
                    name: format!("@etb_{addr:08X}"),
                    address: addr as u64,
                    section: Some(extab_section_index),
                    size: size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local | ObjSymbolFlags::Hidden),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                false,
            )?;
        }
    }

    Ok(())
}
