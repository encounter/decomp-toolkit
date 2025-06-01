use std::{
    io,
    io::{Read, Seek, SeekFrom},
};

use anyhow::Result;
use io::{Error, ErrorKind};

use crate::{
    obj::{ObjSymbol, ObjSymbolKind, SectionIndex},
    util::{
        dol::{DolLike, DolSection, DolSectionKind},
        reader::{
            read_string, read_vec, read_vec_args, struct_size, Endian, FromReader, DYNAMIC_SIZE,
        },
    },
};

pub const ALF_MAGIC: [u8; 4] = *b"RBOF";

#[derive(Debug, Clone)]
pub struct AlfFile {
    pub header: AlfHeader,
    pub sections: Vec<DolSection>,
    pub symbols: Vec<AlfSymbol>,
}

impl FromReader for AlfFile {
    type Args = ();

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let header = AlfHeader::from_reader(reader, e)?;
        if !matches!(header.version, 104 | 105) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported ALF version: {}", header.version),
            ));
        }
        let alf_sections: Vec<AlfSection> = read_vec(reader, header.section_count as usize, e)?;
        let symtab =
            AlfSymTab::from_reader_args(reader, e, AlfVersionArgs { version: header.version })?;

        // Infer section types from data size and symbol typeFs
        let mut sections = Vec::with_capacity(alf_sections.len());
        for section in &alf_sections {
            let kind =
                if section.data_size == 0 { DolSectionKind::Bss } else { DolSectionKind::Data };
            sections.push(DolSection {
                address: section.address,
                file_offset: section.file_offset,
                data_size: section.data_size,
                size: section.size,
                kind,
                index: sections.len() as SectionIndex,
            });
        }
        for sym in &symtab.symbols {
            // Section IDs are 1-based
            if sym.section == 0 {
                return Err(Error::new(ErrorKind::InvalidData, "invalid ALF symbol section"));
            }
            if sym.kind == AlfSymbolKind::Function {
                sections[sym.section as usize - 1].kind = DolSectionKind::Text;
            }
        }

        Ok(Self { header, sections, symbols: symtab.symbols })
    }
}

impl DolLike for AlfFile {
    fn sections(&self) -> &[DolSection] { &self.sections }

    fn symbols(&self) -> &[AlfSymbol] { &self.symbols }

    fn entry_point(&self) -> u32 { self.header.entry }

    fn has_unified_bss(&self) -> bool { false }
}

#[derive(Debug, Clone)]
pub struct AlfHeader {
    pub version: u32,
    pub entry: u32,
    pub section_count: u32,
}

impl FromReader for AlfHeader {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        4,                // magic
        u32::STATIC_SIZE, // version
        u32::STATIC_SIZE, // entry
        u32::STATIC_SIZE, // section_count
    ]);

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        if <[u8; 4]>::from_reader(reader, e)? != ALF_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "invalid ALF magic"));
        }
        Ok(Self {
            version: <_>::from_reader(reader, e)?,
            entry: <_>::from_reader(reader, e)?,
            section_count: <_>::from_reader(reader, e)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AlfSection {
    pub address: u32,
    pub data_size: u32,
    pub size: u32,
    pub file_offset: u32,
}

impl FromReader for AlfSection {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // address
        u32::STATIC_SIZE, // data_size
        u32::STATIC_SIZE, // size
    ]);

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let result = Self {
            address: <_>::from_reader(reader, e)?,
            data_size: <_>::from_reader(reader, e)?,
            size: <_>::from_reader(reader, e)?,
            file_offset: reader.stream_position()? as u32,
        };
        reader.seek(SeekFrom::Current(result.data_size as i64))?;
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlfSymbolKind {
    Function,
    Object,
}

impl FromReader for AlfSymbolKind {
    type Args = ();

    const STATIC_SIZE: usize = u32::STATIC_SIZE;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        match u32::from_reader(reader, e)? {
            0 => Ok(Self::Function),
            1 => Ok(Self::Object),
            v => Err(Error::new(ErrorKind::InvalidData, format!("invalid ALF symbol kind: {v}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlfSymbol {
    pub name: String,
    pub demangled_name: String,
    pub address: u32,
    pub size: u32,
    pub kind: AlfSymbolKind,
    pub section: u32,
    pub unk: u32,
}

#[derive(Copy, Clone)]
pub struct AlfVersionArgs {
    pub version: u32,
}

impl FromReader for AlfSymbol {
    type Args = AlfVersionArgs;

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            name: read_string::<u32, _>(reader, e)?,
            demangled_name: read_string::<u32, _>(reader, e)?,
            address: <_>::from_reader(reader, e)?,
            size: <_>::from_reader(reader, e)?,
            kind: <_>::from_reader(reader, e)?,
            section: <_>::from_reader(reader, e)?,
            unk: if args.version >= 105 { <_>::from_reader(reader, e)? } else { 0 },
        })
    }
}

impl AlfSymbol {
    pub fn to_obj_symbol(&self) -> Result<ObjSymbol> {
        let kind = match self.kind {
            AlfSymbolKind::Function => ObjSymbolKind::Function,
            AlfSymbolKind::Object => ObjSymbolKind::Object,
        };
        let (name, name_hash) = if self.name.starts_with('#') {
            let hash_str = self.name.trim_start_matches('#');
            let hash = u32::from_str_radix(hash_str, 16)?;
            let name = match self.kind {
                AlfSymbolKind::Function => format!("fn_{:08X}", self.address),
                AlfSymbolKind::Object => format!("lbl_{:08X}", self.address),
            };
            (name, Some(hash))
        } else {
            (self.name.clone(), None)
        };
        let (demangled_name, demangled_name_hash) = if self.demangled_name.starts_with('#') {
            let hash_str = self.demangled_name.trim_start_matches('#');
            let hash = u32::from_str_radix(hash_str, 16)?;
            (None, Some(hash))
        } else {
            (Some(self.demangled_name.clone()), None)
        };
        Ok(ObjSymbol {
            name,
            demangled_name,
            address: self.address as u64,
            section: Some(self.section as SectionIndex - 1),
            size: self.size as u64,
            size_known: true,
            flags: Default::default(),
            kind,
            align: None,
            data_kind: Default::default(),
            name_hash,
            demangled_name_hash,
        })
    }
}

#[derive(Debug)]
pub struct AlfSymTab {
    pub symbols: Vec<AlfSymbol>,
}

impl FromReader for AlfSymTab {
    type Args = AlfVersionArgs;

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let _size = u32::from_reader(reader, e)?;
        let count = u32::from_reader(reader, e)? as usize;
        let symbols = read_vec_args(reader, count, e, args)?;
        Ok(Self { symbols })
    }
}

pub const ALF_HASH_SEED: u32 = 0x1505;

pub fn alf_hash(mut h: u32, s: &str) -> u32 {
    for c in s.bytes() {
        h *= 33;
        h ^= c as u32;
    }
    h
}
