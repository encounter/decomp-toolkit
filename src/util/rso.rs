use std::{
    io,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::{anyhow, ensure, Result};
use cwdemangle::{demangle, DemangleOptions};

use crate::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
    util::{
        file::{read_c_string, read_string},
        reader::{struct_size, Endian, FromReader, ToWriter, DYNAMIC_SIZE},
    },
};

/// For RSO references to the DOL, the sections are hardcoded.
pub const DOL_SECTION_NAMES: [Option<&str>; 14] = [
    None, // s_null
    Some(".init"),
    Some(".text"),
    Some(".ctors"),
    Some(".dtors"),
    Some(".rodata"),
    Some(".data"),
    Some(".bss"),
    Some(".sdata"),
    Some(".sdata2"),
    None, // s_zero
    Some(".sbss"),
    Some(".sbss2"),
    None, // s_zero2
];

pub const RSO_SECTION_NAMES: [&str; 7] =
    [".init", ".text", ".ctors", ".dtors", ".rodata", ".data", ".bss"];

/// extabindex section index.
pub const DOL_SECTION_ETI: u32 = 241;
/// ABS symbol section index.
pub const DOL_SECTION_ABS: u32 = 65521;

#[derive(Default)]
pub struct RsoHeader {
    // Pointer to the next module, forming a linked list. Always 0, filled in at runtime.
    // pub next: u32,
    // Pointer to the previous module, forming a linked list. Always 0, filled in at runtime.
    // pub prev: u32,
    /// Number of sections contained in the file.
    pub num_sections: u32,
    /// Offset to the section info table. Always 0x58.
    pub section_info_offset: u32,
    /// Offset to the module name. Can be 0, in which case this module doesn't contain a name string.
    pub name_offset: u32,
    /// Size of the module name string.
    pub name_size: u32,
    /// Module version number. Always 1.
    pub version: u32,
    /// Size of the BSS section, which is allocated at runtime (not included in the file).
    pub bss_size: u32,
    /// Section index of the prolog function, which is called when the module is linked.
    /// 0 if this module doesn't contain a prolog function.
    pub prolog_section: u8,
    /// Section index of the epilog function, which is called when the module is unlinked.
    /// 0 if this module doesn't contain an epilog function.
    pub epilog_section: u8,
    /// Section index of the unresolved function, which is called if the module attempts to call
    /// an unlinked function. 0 if this module doesn't contain an unresolved function.
    pub unresolved_section: u8,
    // Section index of the BSS section. Always 0, filled in at runtime.
    // pub bss_section: u8,
    /// Section-relative offset of the prolog function.
    /// 0 if this module doesn't contain a prolog function.
    pub prolog_offset: u32,
    /// Section-relative offset of the epilog function.
    /// 0 if this module doesn't contain an epilog function.
    pub epilog_offset: u32,
    /// Section-relative offset of the unresolved function.
    /// 0 if this module doesn't contain an unresolved function.
    pub unresolved_offset: u32,
    /// Absolute offset of the relocation table for internal relocations
    /// (relocations for symbols within this module).
    pub internal_rel_offset: u32,
    /// Size of the relocation table for internal relocations.
    pub internal_rel_size: u32,
    /// Absolute offset of the relocation table for external relocations
    /// (relocations for symbols within other modules).
    pub external_rel_offset: u32,
    /// Size of the relocation table for external relocations.
    pub external_rel_size: u32,
    /// Absolute offset of the symbol table for exports (symbols within this module).
    pub export_table_offset: u32,
    /// Size of the symbol table for exports.
    pub export_table_size: u32,
    /// Absolute offset of the string table containing export symbol names.
    pub export_table_name_offset: u32,
    /// Absolute offset of the symbol table for imports
    /// (symbols within other modules, referenced by this one).
    pub import_table_offset: u32,
    /// Size of the symbol table for imports.
    pub import_table_size: u32,
    /// Absolute offset of the string table containing import symbol names.
    pub import_table_name_offset: u32,
}

impl RsoHeader {
    pub fn new() -> Self { Self { version: 1, ..Default::default() } }
}

impl FromReader for RsoHeader {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // next
        u32::STATIC_SIZE, // prev
        u32::STATIC_SIZE, // num_sections
        u32::STATIC_SIZE, // section_info_offset
        u32::STATIC_SIZE, // name_offset
        u32::STATIC_SIZE, // name_size
        u32::STATIC_SIZE, // version
        u32::STATIC_SIZE, // bss_size
        u8::STATIC_SIZE,  // prolog_section
        u8::STATIC_SIZE,  // epilog_section
        u8::STATIC_SIZE,  // unresolved_section
        u8::STATIC_SIZE,  // bss_section
        u32::STATIC_SIZE, // prolog_offset
        u32::STATIC_SIZE, // epilog_offset
        u32::STATIC_SIZE, // unresolved_offset
        u32::STATIC_SIZE, // internal_rel_offset
        u32::STATIC_SIZE, // internal_rel_size
        u32::STATIC_SIZE, // external_rel_offset
        u32::STATIC_SIZE, // external_rel_size
        u32::STATIC_SIZE, // export_table_offset
        u32::STATIC_SIZE, // export_table_size
        u32::STATIC_SIZE, // export_table_name_offset
        u32::STATIC_SIZE, // import_table_offset
        u32::STATIC_SIZE, // import_table_size
        u32::STATIC_SIZE, // import_table_name_offset
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let next = u32::from_reader(reader, e)?;
        if next != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected 'next' to be 0, got {next:#X}"),
            ));
        }
        let prev = u32::from_reader(reader, e)?;
        if prev != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected 'prev' to be 0, got {prev:#X}"),
            ));
        }
        let num_sections = u32::from_reader(reader, e)?;
        let section_info_offset = u32::from_reader(reader, e)?;
        let name_offset = u32::from_reader(reader, e)?;
        let name_size = u32::from_reader(reader, e)?;
        let version = u32::from_reader(reader, e)?;
        let bss_size = u32::from_reader(reader, e)?;
        let prolog_section = u8::from_reader(reader, e)?;
        let epilog_section = u8::from_reader(reader, e)?;
        let unresolved_section = u8::from_reader(reader, e)?;
        let bss_section = u8::from_reader(reader, e)?;
        if bss_section != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected 'bssSection' to be 0, got {bss_section:#X}"),
            ));
        }
        let prolog_offset = u32::from_reader(reader, e)?;
        let epilog_offset = u32::from_reader(reader, e)?;
        let unresolved_offset = u32::from_reader(reader, e)?;
        let internal_rel_offset = u32::from_reader(reader, e)?;
        let internal_rel_size = u32::from_reader(reader, e)?;
        let external_rel_offset = u32::from_reader(reader, e)?;
        let external_rel_size = u32::from_reader(reader, e)?;
        let export_table_offset = u32::from_reader(reader, e)?;
        let export_table_size = u32::from_reader(reader, e)?;
        let export_table_name_offset = u32::from_reader(reader, e)?;
        let import_table_offset = u32::from_reader(reader, e)?;
        let import_table_size = u32::from_reader(reader, e)?;
        let import_table_name_offset = u32::from_reader(reader, e)?;

        Ok(Self {
            num_sections,
            section_info_offset,
            name_offset,
            name_size,
            version,
            bss_size,
            prolog_section,
            epilog_section,
            unresolved_section,
            prolog_offset,
            epilog_offset,
            unresolved_offset,
            internal_rel_offset,
            internal_rel_size,
            external_rel_offset,
            external_rel_size,
            export_table_offset,
            export_table_size,
            export_table_name_offset,
            import_table_offset,
            import_table_size,
            import_table_name_offset,
        })
    }
}

impl ToWriter for RsoHeader {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        (0u64).to_writer(writer, e)?; // next and prev
        self.num_sections.to_writer(writer, e)?;
        self.section_info_offset.to_writer(writer, e)?;
        self.name_offset.to_writer(writer, e)?;
        self.name_size.to_writer(writer, e)?;
        self.version.to_writer(writer, e)?;
        self.bss_size.to_writer(writer, e)?;
        self.prolog_section.to_writer(writer, e)?;
        self.epilog_section.to_writer(writer, e)?;
        self.unresolved_section.to_writer(writer, e)?;
        (0u8).to_writer(writer, e)?; // bss_section
        self.prolog_offset.to_writer(writer, e)?;
        self.epilog_offset.to_writer(writer, e)?;
        self.unresolved_offset.to_writer(writer, e)?;
        self.internal_rel_offset.to_writer(writer, e)?;
        self.internal_rel_size.to_writer(writer, e)?;
        self.external_rel_offset.to_writer(writer, e)?;
        self.external_rel_size.to_writer(writer, e)?;
        self.export_table_offset.to_writer(writer, e)?;
        self.export_table_size.to_writer(writer, e)?;
        self.export_table_name_offset.to_writer(writer, e)?;
        self.import_table_offset.to_writer(writer, e)?;
        self.import_table_size.to_writer(writer, e)?;
        self.import_table_name_offset.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct RsoSectionHeader {
    /// Absolute offset of the section.
    /// The lowest bit is set if the section is executable.
    pub offset_and_flags: u32,
    /// Size of the section.
    pub size: u32,
}

impl FromReader for RsoSectionHeader {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // offset
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

impl ToWriter for RsoSectionHeader {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset_and_flags.to_writer(writer, e)?;
        self.size.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl RsoSectionHeader {
    #[allow(dead_code)]
    fn new(offset: u32, size: u32, exec: bool) -> Self {
        Self { offset_and_flags: offset | (exec as u32), size }
    }

    pub fn offset(&self) -> u32 { self.offset_and_flags & !1 }

    pub fn size(&self) -> u32 { self.size }

    pub fn exec(&self) -> bool { self.offset_and_flags & 1 != 0 }
}

pub struct RsoRelocation {
    /// Absolute offset of this relocation (relative to the start of the RSO file).
    pub offset: u32,
    /// For internal relocations, this is the section index of the symbol being patched to.
    /// For external relocations, this is the index of the symbol within the import symbol table.
    /// The lowest 8 bits are the relocation type.
    pub id_and_type: u32,
    /// For internal relocations, this is the section-relative offset of the target symbol.
    /// For external relocations, this is unused and always 0 (the offset is calculated using the
    /// import symbol table).
    pub target_offset: u32,
}

impl FromReader for RsoRelocation {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // offset
        u32::STATIC_SIZE, // id_and_type
        u32::STATIC_SIZE, // sym_offset
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            offset: u32::from_reader(reader, e)?,
            id_and_type: u32::from_reader(reader, e)?,
            target_offset: u32::from_reader(reader, e)?,
        })
    }
}

impl ToWriter for RsoRelocation {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset.to_writer(writer, e)?;
        self.id_and_type.to_writer(writer, e)?;
        self.target_offset.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl RsoRelocation {
    #[allow(dead_code)]
    pub fn new(offset: u32, id: u32, rel_type: u8, sym_offset: u32) -> Self {
        Self { offset, id_and_type: (id << 8) | rel_type as u32, target_offset: sym_offset }
    }

    pub fn offset(&self) -> u32 { self.offset }

    pub fn id(&self) -> u32 { (self.id_and_type & 0xFFFFFF00) >> 8 }

    pub fn rel_type(&self) -> u8 { (self.id_and_type & 0xFF) as u8 }

    pub fn sym_offset(&self) -> u32 { self.target_offset }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RsoSymbolKind {
    Import,
    Export,
}

#[derive(Debug)]
pub struct RsoSymbol {
    /// Relative offset into the name table pointed to in the header,
    /// which points to the name of this symbol.
    pub name_offset: u32,
    /// The section-relative offset to the symbol. This is always 0 for imports.
    pub offset: u32,
    /// For exports, index of the section that contains this symbol.
    /// For imports, offset of the first relocation that use this symbol
    pub section_index: u32,
    /// A hash of the symbol name. Only present for exports.
    pub hash: Option<u32>,
}

impl FromReader for RsoSymbol {
    type Args = RsoSymbolKind;

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, e: Endian, args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            name_offset: u32::from_reader(reader, e)?,
            offset: u32::from_reader(reader, e)?,
            section_index: u32::from_reader(reader, e)?,
            hash: if args == RsoSymbolKind::Export {
                Some(u32::from_reader(reader, e)?)
            } else {
                None
            },
        })
    }
}

impl ToWriter for RsoSymbol {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.name_offset.to_writer(writer, e)?;
        self.offset.to_writer(writer, e)?;
        self.section_index.to_writer(writer, e)?;
        if let Some(hash) = self.hash {
            // Since the nature of the value is not numeric, we must preserve the order of the bytes
            writer.write_all(&hash.to_ne_bytes())?;
        }
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

pub fn process_rso<R>(reader: &mut R) -> Result<ObjInfo>
where R: Read + Seek + ?Sized {
    let header = RsoHeader::from_reader(reader, Endian::Big)?;
    let mut sections = Vec::with_capacity(header.num_sections as usize);
    reader.seek(SeekFrom::Start(header.section_info_offset as u64))?;
    let mut total_bss_size = 0;
    for idx in 0..header.num_sections {
        let section = RsoSectionHeader::from_reader(reader, Endian::Big)?;
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
            reader.read_exact(&mut data)?;
            reader.seek(SeekFrom::Start(position))?;
            data
        };

        // println!("Section {} offset {:#X} size {:#X}", idx, offset, size);

        sections.push(ObjSection {
            name: format!(".section{idx}"),
            kind: if offset == 0 {
                ObjSectionKind::Bss
            } else if section.exec() {
                ObjSectionKind::Code
            } else {
                ObjSectionKind::Data
            },
            address: 0,
            size: size as u64,
            data,
            align: 0,
            elf_index: idx as SectionIndex,
            relocations: Default::default(),
            virtual_address: None, // TODO option to set?
            file_offset: offset as u64,
            section_known: false,
            splits: Default::default(),
        });
        if offset == 0 {
            total_bss_size += size;
        }
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
                .find(|&(_, section)| section.elf_index == rel_section_idx as SectionIndex)
                .ok_or_else(|| anyhow!("Failed to locate {name} section {rel_section_idx}"))?;
            log::debug!("Adding {name} section {rel_section_idx} offset {offset:#X}");
            symbols.push(ObjSymbol {
                name: name.to_string(),
                address: offset as u64,
                section: Some(section_index as SectionIndex),
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            });
        }
        Ok(())
    };
    add_symbol(header.prolog_section, header.prolog_offset, "_prolog")?;
    add_symbol(header.epilog_section, header.epilog_offset, "_epilog")?;
    add_symbol(header.unresolved_section, header.unresolved_offset, "_unresolved")?;

    reader.seek(SeekFrom::Start(header.external_rel_offset as u64))?;
    while reader.stream_position()? < (header.external_rel_offset + header.external_rel_size) as u64
    {
        let reloc = RsoRelocation::from_reader(reader, Endian::Big)?;
        log::debug!(
            "Reloc offset: {:#X}, id: {}, type: {}, sym offset: {:#X}",
            reloc.offset(),
            reloc.id(),
            reloc.rel_type(),
            reloc.sym_offset()
        );
    }

    reader.seek(SeekFrom::Start(header.export_table_offset as u64))?;
    while reader.stream_position()? < (header.export_table_offset + header.export_table_size) as u64
    {
        let symbol = RsoSymbol::from_reader_args(reader, Endian::Big, RsoSymbolKind::Export)?;
        let name =
            read_c_string(reader, (header.export_table_name_offset + symbol.name_offset) as u64)?;
        let calc = symbol_hash(&name);
        let hash_n = symbol.hash.unwrap_or_default();
        ensure!(
            hash_n == calc,
            "Mismatched calculated hash for symbol {}: {:#X} != {:#X}",
            name,
            hash_n,
            calc
        );
        let demangled_name = demangle(&name, &DemangleOptions::default());
        let section = sections
            .iter()
            .enumerate()
            .find(|&(_, section)| section.elf_index == symbol.section_index as SectionIndex)
            .map(|(idx, _)| idx)
            // HACK: selfiles won't have any sections
            .unwrap_or(symbol.section_index as usize);
        log::debug!(
            "Export: {}, sym off: {:#X}, section: {}, ELF hash: {:#X}",
            demangled_name.as_deref().unwrap_or(&name),
            symbol.offset,
            symbol.section_index,
            hash_n
        );
        symbols.push(ObjSymbol {
            name,
            demangled_name,
            address: symbol.offset as u64,
            section: Some(section as SectionIndex),
            ..Default::default()
        });
    }
    reader.seek(SeekFrom::Start(header.import_table_offset as u64))?;
    while reader.stream_position()? < (header.import_table_offset + header.import_table_size) as u64
    {
        let symbol = RsoSymbol::from_reader_args(reader, Endian::Big, RsoSymbolKind::Import)?;
        let name =
            read_c_string(reader, (header.import_table_name_offset + symbol.name_offset) as u64)?;
        log::debug!(
            "Import: {}, sym off: {}, section: {}",
            name,
            symbol.offset,
            symbol.section_index
        );
    }

    let name = match header.name_offset {
        0 => String::new(),
        _ => read_string(reader, header.name_offset as u64, header.name_size as usize)?,
    };

    let obj = ObjInfo::new(ObjKind::Relocatable, ObjArchitecture::PowerPc, name, symbols, sections);
    Ok(obj)
}

pub fn symbol_hash(s: &str) -> u32 {
    s.bytes().fold(0u32, |hash, c| {
        let mut m = (hash << 4).wrapping_add(c as u32);
        let n = m & 0xF0000000;
        if n != 0 {
            m ^= n >> 24;
        }
        m & !n
    })
}
