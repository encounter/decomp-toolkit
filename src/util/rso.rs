use std::{
    io,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::{Result, anyhow, bail, ensure};
use cwdemangle::{DemangleOptions, demangle};
use object::elf;

use crate::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
    util::{
        file::{read_c_string, read_string},
        reader::{DYNAMIC_SIZE, Endian, FromReader, ToWriter, struct_size},
        rel::RelReloc,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            hash.to_writer(writer, e)?;
        }
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// Loads an RSO module as a relocatable object.
///
/// Internal relocations are stored as [`ObjInfo::unresolved_relocations`] against the module
/// itself. Imports are resolved by name at runtime, so each import becomes an undefined symbol,
/// with relocations against it added directly to the referencing section.
pub fn process_rso<R>(reader: &mut R, name: &str, module_id: u32) -> Result<(RsoModule, ObjInfo)>
where R: Read + Seek + ?Sized {
    let module = RsoModule::read(reader)?;
    ensure!(!module.is_sel, "Expected an RSO module, but {name} is a SEL");

    // The executable flag is not reliably set, so locate .text using the entry points instead.
    let text_section = module
        .sections
        .iter()
        .position(|s| s.exec && s.size != 0)
        .map(|idx| idx as u8)
        .or(module.prolog.map(|(section, _)| section))
        .or(module.epilog.map(|(section, _)| section))
        .or(module.unresolved.map(|(section, _)| section));
    let mut sections = Vec::with_capacity(module.sections.len());
    let mut has_bss = false;
    for (idx, section) in module.sections.iter().enumerate() {
        if section.size == 0 {
            continue;
        }
        let (name, kind, section_known) = if section.offset == 0 {
            ensure!(!has_bss, "Multiple BSS sections in RSO");
            has_bss = true;
            (".bss".to_string(), ObjSectionKind::Bss, true)
        } else if text_section == Some(idx as u8) {
            (".text".to_string(), ObjSectionKind::Code, true)
        } else {
            (format!(".section{idx}"), ObjSectionKind::Data, false)
        };
        sections.push(ObjSection {
            name,
            kind,
            address: 0,
            size: section.size as u64,
            data: section.data.clone(),
            // RSOs don't store the BSS alignment. Others are determined later from file offsets.
            align: if section.offset == 0 { 8 } else { 0 },
            elf_index: idx as SectionIndex,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: section.offset as u64,
            section_known,
            splits: Default::default(),
        });
    }
    let section_index = |rso_index: u32, what: &dyn std::fmt::Display| -> Result<SectionIndex> {
        sections
            .iter()
            .position(|section| section.elf_index == rso_index as SectionIndex)
            .map(|idx| idx as SectionIndex)
            .ok_or_else(|| anyhow!("Failed to locate section {rso_index} for {what}"))
    };

    let mut symbols = Vec::<ObjSymbol>::new();
    let mut add_symbol = |rso_section: u32, offset: u32, name: &str| -> Result<()> {
        let section = section_index(rso_section, &name)?;
        if symbols.iter().any(|s| s.name == name) {
            return Ok(());
        }
        let mut flags = ObjSymbolFlagSet(ObjSymbolFlags::Global.into());
        flags.set_force_active(true);
        symbols.push(ObjSymbol {
            name: name.to_string(),
            demangled_name: demangle(name, &DemangleOptions::default()),
            address: offset as u64,
            section: Some(section),
            flags,
            kind: match sections[section as usize].kind {
                ObjSectionKind::Code => ObjSymbolKind::Function,
                _ => ObjSymbolKind::Object,
            },
            ..Default::default()
        });
        Ok(())
    };
    for (entry, name) in
        [(module.prolog, "_prolog"), (module.epilog, "_epilog"), (module.unresolved, "_unresolved")]
    {
        if let Some((section, offset)) = entry {
            add_symbol(section as u32, offset, name)?;
        }
    }
    for export in &module.exports {
        add_symbol(export.section, export.offset, &export.name)?;
    }

    // Locates the section and section-relative address of a relocation by its file offset.
    let locate = |offset: u32| -> Result<(u8, SectionIndex, u32)> {
        sections
            .iter()
            .enumerate()
            .find(|(_, s)| {
                s.kind != ObjSectionKind::Bss
                    && (s.file_offset..s.file_offset + s.size).contains(&(offset as u64))
            })
            .map(|(idx, s)| {
                (s.elf_index as u8, idx as SectionIndex, (offset - s.file_offset as u32) & !3)
            })
            .ok_or_else(|| anyhow!("RSO relocation offset {offset:#X} is not within a section"))
    };

    let mut unresolved_relocations = Vec::with_capacity(module.internal_relocations.len());
    for reloc in &module.internal_relocations {
        let Some(kind) = reloc_kind(reloc.rel_type())? else { continue };
        let (section, _, address) = locate(reloc.offset())?;
        let target_section = u8::try_from(reloc.id())
            .map_err(|_| anyhow!("Invalid RSO relocation target section {}", reloc.id()))?;
        unresolved_relocations.push(RelReloc {
            kind,
            section,
            address,
            module_id,
            target_section,
            addend: reloc.sym_offset(),
            original_section: section,
            original_target_section: target_section,
        });
    }

    let mut external_relocations = Vec::with_capacity(module.external_relocations.len());
    for reloc in &module.external_relocations {
        let Some(kind) = reloc_kind(reloc.rel_type())? else { continue };
        let (_, section, address) = locate(reloc.offset())?;
        external_relocations.push((section, address, kind, reloc.id() as usize));
    }

    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        name.to_string(),
        symbols,
        sections,
    );
    obj.module_id = module_id;
    obj.unresolved_relocations = unresolved_relocations;

    let mut import_symbols = Vec::with_capacity(module.imports.len());
    for name in &module.imports {
        import_symbols.push(obj.symbols.add_direct(ObjSymbol {
            name: name.clone(),
            demangled_name: demangle(name, &DemangleOptions::default()),
            ..Default::default()
        })?);
    }
    for (section, address, kind, import) in external_relocations {
        obj.sections[section]
            .relocations
            .insert(address, ObjReloc {
                kind,
                target_symbol: import_symbols[import],
                addend: 0,
                module: None,
            })
            .map_err(|e| anyhow!("In RSO section {}: {e}", obj.sections[section].name))?;
    }
    Ok((module, obj))
}

fn reloc_kind(rel_type: u8) -> Result<Option<ObjRelocKind>> {
    Ok(Some(match rel_type as u32 {
        elf::R_PPC_NONE => return Ok(None),
        elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 => ObjRelocKind::Absolute,
        elf::R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
        elf::R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
        elf::R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
        elf::R_PPC_REL24 => ObjRelocKind::PpcRel24,
        elf::R_PPC_REL14 => ObjRelocKind::PpcRel14,
        rel_type => bail!("Unhandled RSO relocation type {rel_type}"),
    }))
}

/// A section of an [`RsoModule`].
#[derive(Debug, Clone, Default)]
pub struct RsoSection {
    /// Absolute file offset of the section data. 0 for BSS or unused sections.
    pub offset: u32,
    /// Size of the section.
    pub size: u32,
    /// Whether the executable flag is set.
    pub exec: bool,
    /// Section data. Empty for BSS or unused sections.
    pub data: Vec<u8>,
}

/// An exported symbol of an [`RsoModule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsoExport {
    pub name: String,
    /// Section index, [`DOL_SECTION_ABS`] or [`DOL_SECTION_ETI`].
    pub section: u32,
    /// Section-relative offset (or absolute value for [`DOL_SECTION_ABS`]).
    pub offset: u32,
}

/// A fully parsed RSO or SEL file, which can be written back out byte-for-byte.
#[derive(Debug, Clone, Default)]
pub struct RsoModule {
    /// Whether this is a SEL (static module export list). SELs contain no section data or
    /// relocations, and use a different table layout.
    pub is_sel: bool,
    pub version: u32,
    /// Module name (usually the path of the original PLF or ELF).
    pub name: String,
    /// Section table, including unused entries.
    pub sections: Vec<RsoSection>,
    pub prolog: Option<(u8, u32)>,
    pub epilog: Option<(u8, u32)>,
    pub unresolved: Option<(u8, u32)>,
    /// Exports in table order (sorted by name hash).
    pub exports: Vec<RsoExport>,
    /// Indices into `exports`, in string table order.
    pub export_name_order: Vec<usize>,
    /// Imported symbol names, in table (and string table) order.
    pub imports: Vec<String>,
    /// Relocations against sections of this module.
    pub internal_relocations: Vec<RsoRelocation>,
    /// Relocations against imports. [`RsoRelocation::id`] is an index into `imports`.
    pub external_relocations: Vec<RsoRelocation>,
}

fn read_table<T, R>(reader: &mut R, offset: u32, size: u32, args: T::Args) -> Result<Vec<T>>
where
    T: FromReader,
    T::Args: Copy,
    R: Read + Seek + ?Sized,
{
    reader.seek(SeekFrom::Start(offset as u64))?;
    let end = offset as u64 + size as u64;
    let mut out = Vec::new();
    while reader.stream_position()? < end {
        out.push(T::from_reader_args(reader, Endian::Big, args)?);
    }
    Ok(out)
}

fn pad_to<W>(w: &mut W, align: u64) -> io::Result<u64>
where W: Write + Seek + ?Sized {
    let pos = w.stream_position()?;
    let aligned = pos.next_multiple_of(align);
    for _ in pos..aligned {
        w.write_all(&[0])?;
    }
    Ok(aligned)
}

impl RsoModule {
    pub fn read<R>(reader: &mut R) -> Result<Self>
    where R: Read + Seek + ?Sized {
        let header = RsoHeader::from_reader(reader, Endian::Big)?;
        ensure!(header.version == 1, "Unsupported RSO version {}", header.version);

        reader.seek(SeekFrom::Start(header.section_info_offset as u64))?;
        let mut sections = Vec::with_capacity(header.num_sections as usize);
        let mut total_bss_size = 0;
        for idx in 0..header.num_sections {
            let section = RsoSectionHeader::from_reader(reader, Endian::Big)?;
            let (offset, size) = (section.offset(), section.size());
            let data = if offset == 0 || size == 0 {
                vec![]
            } else {
                let position = reader.stream_position()?;
                reader.seek(SeekFrom::Start(offset as u64))?;
                let mut data = vec![0u8; size as usize];
                reader.read_exact(&mut data).map_err(|e| {
                    anyhow!("Failed to read RSO section {idx} data with size {size:#X}: {e}")
                })?;
                reader.seek(SeekFrom::Start(position))?;
                data
            };
            if offset == 0 {
                total_bss_size += size;
            }
            sections.push(RsoSection { offset, size, exec: section.exec(), data });
        }
        ensure!(
            total_bss_size == header.bss_size,
            "Mismatched BSS size: {:#X} != {:#X}",
            total_bss_size,
            header.bss_size
        );

        let name = match header.name_offset {
            0 => String::new(),
            _ => read_string(reader, header.name_offset as u64, header.name_size as usize)?,
        };

        let raw_exports: Vec<RsoSymbol> = read_table(
            reader,
            header.export_table_offset,
            header.export_table_size,
            RsoSymbolKind::Export,
        )?;
        let mut exports = Vec::with_capacity(raw_exports.len());
        for symbol in &raw_exports {
            let name = read_c_string(
                reader,
                (header.export_table_name_offset + symbol.name_offset) as u64,
            )?;
            let calc = symbol_hash(&name);
            let hash = symbol.hash.unwrap_or_default();
            ensure!(
                hash == calc,
                "Mismatched calculated hash for symbol {}: {:#X} != {:#X}",
                name,
                hash,
                calc
            );
            exports.push(RsoExport { name, section: symbol.section_index, offset: symbol.offset });
        }
        let mut export_name_order = (0..exports.len()).collect::<Vec<_>>();
        export_name_order.sort_by_key(|&i| raw_exports[i].name_offset);

        let raw_imports: Vec<RsoSymbol> = read_table(
            reader,
            header.import_table_offset,
            header.import_table_size,
            RsoSymbolKind::Import,
        )?;
        let mut imports = Vec::with_capacity(raw_imports.len());
        let mut expected_name_offset = 0;
        for symbol in &raw_imports {
            ensure!(
                symbol.name_offset == expected_name_offset,
                "Unexpected RSO import name offset {:#X} (expected {:#X})",
                symbol.name_offset,
                expected_name_offset
            );
            let name = read_c_string(
                reader,
                (header.import_table_name_offset + symbol.name_offset) as u64,
            )?;
            expected_name_offset += name.len() as u32 + 1;
            imports.push(name);
        }

        let internal_relocations: Vec<RsoRelocation> =
            read_table(reader, header.internal_rel_offset, header.internal_rel_size, ())?;
        let external_relocations: Vec<RsoRelocation> =
            read_table(reader, header.external_rel_offset, header.external_rel_size, ())?;
        for reloc in &external_relocations {
            ensure!(
                (reloc.id() as usize) < imports.len(),
                "RSO external relocation references invalid import {}",
                reloc.id()
            );
        }

        let entry = |section: u8, offset: u32| (section != 0).then_some((section, offset));
        Ok(Self {
            is_sel: sections.iter().all(|s| s.size == 0),
            version: header.version,
            name,
            sections,
            prolog: entry(header.prolog_section, header.prolog_offset),
            epilog: entry(header.epilog_section, header.epilog_offset),
            unresolved: entry(header.unresolved_section, header.unresolved_offset),
            exports,
            export_name_order,
            imports,
            internal_relocations,
            external_relocations,
        })
    }

    /// Assigns file offsets to each section with data, given the alignment of each section.
    pub fn layout_sections(&mut self, align: &[u32]) {
        let mut offset = RsoHeader::STATIC_SIZE as u32
            + self.sections.len() as u32 * RsoSectionHeader::STATIC_SIZE as u32;
        for (section, &align) in self.sections.iter_mut().zip(align) {
            if section.data.is_empty() {
                section.offset = 0;
                continue;
            }
            offset = offset.next_multiple_of(align.max(1));
            section.offset = offset;
            offset += section.size;
        }
    }

    /// Writes the module. Section file offsets must be assigned (see [`Self::layout_sections`]).
    pub fn write<W>(&self, w: &mut W) -> Result<()>
    where W: Write + Seek + ?Sized {
        let mut header = RsoHeader::new();
        header.version = self.version;
        header.num_sections = self.sections.len() as u32;
        header.section_info_offset = RsoHeader::STATIC_SIZE as u32;
        if let Some((section, offset)) = self.prolog {
            (header.prolog_section, header.prolog_offset) = (section, offset);
        }
        if let Some((section, offset)) = self.epilog {
            (header.epilog_section, header.epilog_offset) = (section, offset);
        }
        if let Some((section, offset)) = self.unresolved {
            (header.unresolved_section, header.unresolved_offset) = (section, offset);
        }

        // Section table and data
        w.seek(SeekFrom::Start(header.section_info_offset as u64))?;
        for section in &self.sections {
            RsoSectionHeader {
                offset_and_flags: section.offset | section.exec as u32,
                size: section.size,
            }
            .to_writer(w, Endian::Big)?;
        }
        for (idx, section) in self.sections.iter().enumerate() {
            if section.data.is_empty() {
                if section.offset == 0 {
                    header.bss_size += section.size;
                }
                continue;
            }
            let pos = w.stream_position()?;
            ensure!(
                section.offset as u64 >= pos,
                "RSO section {} offset {:#X} overlaps previous data (at {:#X})",
                idx,
                section.offset,
                pos
            );
            for _ in pos..section.offset as u64 {
                w.write_all(&[0])?;
            }
            w.write_all(&section.data)?;
        }

        // Module name
        header.name_offset = pad_to(w, 4)? as u32;
        header.name_size = self.name.len() as u32;
        w.write_all(self.name.as_bytes())?;
        w.write_all(&[0])?;

        // String tables
        let mut export_names = Vec::<u8>::new();
        let mut export_name_offsets = vec![0u32; self.exports.len()];
        ensure!(
            self.export_name_order.len() == self.exports.len(),
            "RSO export name order length mismatch"
        );
        for &idx in &self.export_name_order {
            export_name_offsets[idx] = export_names.len() as u32;
            export_names.extend_from_slice(self.exports[idx].name.as_bytes());
            export_names.push(0);
        }
        let mut import_names = Vec::<u8>::new();
        let mut import_name_offsets = Vec::with_capacity(self.imports.len());
        for name in &self.imports {
            import_name_offsets.push(import_names.len() as u32);
            import_names.extend_from_slice(name.as_bytes());
            import_names.push(0);
        }

        // Exports
        header.export_table_offset = pad_to(w, 4)? as u32;
        header.export_table_size = self.exports.len() as u32 * 16;
        for (export, &name_offset) in self.exports.iter().zip(&export_name_offsets) {
            RsoSymbol {
                name_offset,
                offset: export.offset,
                section_index: export.section,
                hash: Some(symbol_hash(&export.name)),
            }
            .to_writer(w, Endian::Big)?;
        }
        if !self.is_sel {
            header.export_table_name_offset = pad_to(w, 4)? as u32;
            w.write_all(&export_names)?;
        }

        // External relocations
        header.external_rel_offset = pad_to(w, 4)? as u32;
        header.external_rel_size = self.external_relocations.len() as u32 * 12;
        for reloc in &self.external_relocations {
            reloc.to_writer(w, Endian::Big)?;
        }

        // Imports
        header.import_table_offset = pad_to(w, 4)? as u32;
        header.import_table_size = self.imports.len() as u32 * 12;
        for (idx, &name_offset) in import_name_offsets.iter().enumerate() {
            // Offset of the first external relocation that references this import
            let first_reloc = self
                .external_relocations
                .iter()
                .position(|r| r.id() as usize == idx)
                .map_or(u32::MAX, |i| i as u32 * 12);
            RsoSymbol { name_offset, offset: 0, section_index: first_reloc, hash: None }
                .to_writer(w, Endian::Big)?;
        }
        if self.is_sel {
            // SELs place the (empty) relocation tables before the string tables
            header.internal_rel_offset = header.import_table_offset;
            header.export_table_name_offset = pad_to(w, 4)? as u32;
            w.write_all(&export_names)?;
        }
        header.import_table_name_offset = pad_to(w, 4)? as u32;
        w.write_all(&import_names)?;

        // Internal relocations
        if !self.is_sel {
            header.internal_rel_offset = pad_to(w, 4)? as u32;
        }
        header.internal_rel_size = self.internal_relocations.len() as u32 * 12;
        for reloc in &self.internal_relocations {
            reloc.to_writer(w, Endian::Big)?;
        }

        pad_to(w, 32)?;
        w.seek(SeekFrom::Start(0))?;
        header.to_writer(w, Endian::Big)?;
        Ok(())
    }
}

/// Sorts a slice using the same (unstable) algorithm as the Microsoft C runtime's `qsort`.
///
/// The official RSO tooling sorts external relocations by import index using `qsort`, so the
/// resulting order of relocations for the same import depends on the exact algorithm used.
pub fn msvc_qsort<T, F>(data: &mut [T], mut compare: F)
where F: FnMut(&T, &T) -> std::cmp::Ordering {
    use std::cmp::Ordering::{Equal, Greater};
    const CUTOFF: usize = 8;
    if data.len() < 2 {
        return;
    }
    let mut stack = vec![(0usize, data.len() - 1)];
    while let Some((mut lo, mut hi)) = stack.pop() {
        loop {
            let size = hi - lo + 1;
            if size <= CUTOFF {
                // Selection sort: repeatedly move the largest element to the end
                while hi > lo {
                    let mut max = lo;
                    for p in lo + 1..=hi {
                        if compare(&data[p], &data[max]) == Greater {
                            max = p;
                        }
                    }
                    data.swap(max, hi);
                    hi -= 1;
                }
                break;
            }

            // Median of three
            let mut mid = lo + size / 2;
            if compare(&data[lo], &data[mid]) == Greater {
                data.swap(lo, mid);
            }
            if compare(&data[lo], &data[hi]) == Greater {
                data.swap(lo, hi);
            }
            if compare(&data[mid], &data[hi]) == Greater {
                data.swap(mid, hi);
            }

            // Partition
            let mut loguy = lo;
            let mut higuy = hi;
            loop {
                if mid > loguy {
                    loguy += 1;
                    while loguy < mid && compare(&data[loguy], &data[mid]) != Greater {
                        loguy += 1;
                    }
                }
                if mid <= loguy {
                    loguy += 1;
                    while loguy <= hi && compare(&data[loguy], &data[mid]) != Greater {
                        loguy += 1;
                    }
                }
                higuy -= 1;
                while higuy > mid && compare(&data[higuy], &data[mid]) == Greater {
                    higuy -= 1;
                }
                if higuy < loguy {
                    break;
                }
                data.swap(loguy, higuy);
                if mid == higuy {
                    mid = loguy;
                }
            }

            // Skip elements equal to the pivot
            higuy += 1;
            if mid < higuy {
                higuy -= 1;
                while higuy > mid && compare(&data[higuy], &data[mid]) == Equal {
                    higuy -= 1;
                }
            }
            if mid >= higuy {
                higuy -= 1;
                while higuy > lo && compare(&data[higuy], &data[mid]) == Equal {
                    higuy -= 1;
                }
            }

            // Sort [lo, higuy] and [loguy, hi]. The order they're processed in doesn't
            // affect the result.
            if lo < higuy {
                stack.push((lo, higuy));
            }
            if loguy < hi {
                lo = loguy;
            } else {
                break;
            }
        }
    }
}

/// Sorts exports by name hash, as the official tooling does. `exports` should be in string
/// table order, which determines the resulting order of any exports with the same hash.
pub fn sort_exports(exports: &mut [RsoExport]) {
    msvc_qsort(exports, |a, b| symbol_hash(&a.name).cmp(&symbol_hash(&b.name)));
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
