use std::{
    cmp::max,
    collections::BTreeMap,
    fmt::{Display, Formatter, Write},
    io::{BufRead, Cursor, Seek, SeekFrom},
    num::NonZeroU32,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use indent::indent_all_by;
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};

use crate::{
    array_ref,
    util::reader::{Endian, FromBytes, FromReader},
};

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum TagKind {
    Padding = 0x0000,
    ArrayType = 0x0001,
    ClassType = 0x0002,
    EntryPoint = 0x0003,
    EnumerationType = 0x0004,
    FormalParameter = 0x0005,
    GlobalSubroutine = 0x0006,
    GlobalVariable = 0x0007,
    Label = 0x000a,
    LexicalBlock = 0x000b,
    LocalVariable = 0x000c,
    Member = 0x000d,
    PointerType = 0x000f,
    ReferenceType = 0x0010,
    // aka SourceFile
    CompileUnit = 0x0011,
    StringType = 0x0012,
    StructureType = 0x0013,
    Subroutine = 0x0014,
    SubroutineType = 0x0015,
    Typedef = 0x0016,
    UnionType = 0x0017,
    UnspecifiedParameters = 0x0018,
    Variant = 0x0019,
    CommonBlock = 0x001a,
    CommonInclusion = 0x001b,
    Inheritance = 0x001c,
    InlinedSubroutine = 0x001d,
    Module = 0x001e,
    PtrToMemberType = 0x001f,
    SetType = 0x0020,
    SubrangeType = 0x0021,
    WithStmt = 0x0022,
    // User types
    MwOverlayBranch = 0x4080,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum FundType {
    WideChar = 0x0000, // Likely an MW bug
    Char = 0x0001,
    SignedChar = 0x0002,
    UnsignedChar = 0x0003,
    Short = 0x0004,
    SignedShort = 0x0005,
    UnsignedShort = 0x0006,
    Integer = 0x0007,
    SignedInteger = 0x0008,
    UnsignedInteger = 0x0009,
    Long = 0x000a,
    SignedLong = 0x000b,
    UnsignedLong = 0x000c,
    Pointer = 0x000d,
    Float = 0x000e,
    DblPrecFloat = 0x000f,
    ExtPrecFloat = 0x0010,
    Complex = 0x0011,
    DblPrecComplex = 0x0012,
    Void = 0x0014,
    Boolean = 0x0015,
    ExtPrecComplex = 0x0016,
    Label = 0x0017,
    // User types
    LongLong = 0x8008,
    SignedLongLong = 0x8108,
    UnsignedLongLong = 0x8208,
    Int128 = 0xa510,
    Vec2x32Float = 0xac00,
}

impl FundType {
    pub fn size(self) -> Result<u32> {
        Ok(match self {
            FundType::Char | FundType::SignedChar | FundType::UnsignedChar | FundType::Boolean => 1,
            FundType::WideChar
            | FundType::Short
            | FundType::SignedShort
            | FundType::UnsignedShort => 2,
            FundType::Integer | FundType::SignedInteger | FundType::UnsignedInteger => 4,
            FundType::Long
            | FundType::SignedLong
            | FundType::UnsignedLong
            | FundType::Pointer
            | FundType::Float => 4,
            FundType::DblPrecFloat
            | FundType::LongLong
            | FundType::SignedLongLong
            | FundType::UnsignedLongLong
            | FundType::Vec2x32Float => 8,
            FundType::Int128 => 16,
            FundType::Void => 0,
            FundType::ExtPrecFloat
            | FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
        })
    }

    pub fn name(self) -> Result<&'static str> {
        Ok(match self {
            FundType::WideChar => "wchar_t",
            FundType::Char => "char",
            FundType::SignedChar => "signed char",
            FundType::UnsignedChar => "unsigned char",
            FundType::Short => "short",
            FundType::SignedShort => "signed short",
            FundType::UnsignedShort => "unsigned short",
            FundType::Integer => "int",
            FundType::SignedInteger => "signed int",
            FundType::UnsignedInteger => "unsigned int",
            FundType::Long => "long",
            FundType::SignedLong => "signed long",
            FundType::UnsignedLong => "unsigned long",
            FundType::Pointer => "void *",
            FundType::Float => "float",
            FundType::DblPrecFloat => "double",
            FundType::ExtPrecFloat => "long double",
            FundType::Void => "void",
            FundType::Boolean => "bool",
            FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
            FundType::LongLong => "long long",
            FundType::SignedLongLong => "signed long long",
            FundType::UnsignedLongLong => "unsigned long long",
            FundType::Int128 => "__int128",
            FundType::Vec2x32Float => "__vec2x32float__",
        })
    }

    pub fn parse_int(value: u16) -> Result<Self, TryFromPrimitiveError<Self>> {
        if value >> 8 == 0x1 {
            // Can appear in erased tags
            Self::try_from(value & 0xFF)
        } else {
            Self::try_from(value)
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Modifier {
    MwPointerTo = 0x00, // Used in erased tags
    PointerTo = 0x01,
    ReferenceTo = 0x02,
    Const = 0x03,
    Volatile = 0x04,
    // User types
}

impl Modifier {
    pub fn parse_int(value: u8) -> Result<Self, TryFromPrimitiveError<Self>> {
        Self::try_from(value & 0x7F) // High bit can appear in erased tags
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum SubscriptFormat {
    FundTypeConstConst = 0x0,
    FundTypeConstLocation = 0x1,
    FundTypeLocationConst = 0x2,
    FundTypeLocationLocation = 0x3,
    UserTypeConstConst = 0x4,
    UserTypeConstLocation = 0x5,
    UserTypeLocationConst = 0x6,
    UserTypeLocationLocation = 0x7,
    ElementType = 0x8,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum LocationOp {
    Register = 0x01,
    BaseRegister = 0x02,
    Address = 0x03,
    Const = 0x04,
    Deref2 = 0x05,
    Deref4 = 0x06,
    Add = 0x07,
    // User types
    MwFpReg = 0x80,
    MwFpDReg = 0x81,
    MwDRef8 = 0x82,
}

const FORM_MASK: u16 = 0xF;

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
enum FormKind {
    Addr = 0x1,
    Ref = 0x2,
    Block2 = 0x3,
    Block4 = 0x4,
    Data2 = 0x5,
    Data4 = 0x6,
    Data8 = 0x7,
    String = 0x8,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum AttributeKind {
    Sibling = 0x0010 | (FormKind::Ref as u16),
    Location = 0x0020 | (FormKind::Block2 as u16),
    Name = 0x0030 | (FormKind::String as u16),
    FundType = 0x0050 | (FormKind::Data2 as u16),
    ModFundType = 0x0060 | (FormKind::Block2 as u16),
    UserDefType = 0x0070 | (FormKind::Ref as u16),
    ModUDType = 0x0080 | (FormKind::Block2 as u16),
    Ordering = 0x0090 | (FormKind::Data2 as u16),
    SubscrData = 0x00a0 | (FormKind::Block2 as u16),
    ByteSize = 0x00b0 | (FormKind::Data4 as u16),
    BitOffset = 0x00c0 | (FormKind::Data2 as u16),
    BitSize = 0x00d0 | (FormKind::Data4 as u16),
    ElementList = 0x00f0 | (FormKind::Block4 as u16),
    StmtList = 0x0100 | (FormKind::Data4 as u16),
    LowPc = 0x0110 | (FormKind::Addr as u16),
    HighPc = 0x0120 | (FormKind::Addr as u16),
    Language = 0x0130 | (FormKind::Data4 as u16),
    Member = 0x0140 | (FormKind::Ref as u16),
    Discr = 0x0150 | (FormKind::Ref as u16),
    DiscrValue = 0x0160 | (FormKind::Block2 as u16),
    StringLength = 0x0190 | (FormKind::Block2 as u16),
    CommonReference = 0x01a0 | (FormKind::Ref as u16),
    CompDir = 0x01b0 | (FormKind::String as u16),
    ConstValueString = 0x01c0 | (FormKind::String as u16),
    ConstValueData2 = 0x01c0 | (FormKind::Data2 as u16),
    ConstValueData4 = 0x01c0 | (FormKind::Data4 as u16),
    ConstValueData8 = 0x01c0 | (FormKind::Data8 as u16),
    ConstValueBlock2 = 0x01c0 | (FormKind::Block2 as u16),
    ConstValueBlock4 = 0x01c0 | (FormKind::Block4 as u16),
    ContainingType = 0x01d0 | (FormKind::Ref as u16),
    DefaultValueAddr = 0x01e0 | (FormKind::Addr as u16),
    DefaultValueData2 = 0x01e0 | (FormKind::Data2 as u16),
    DefaultValueData8 = 0x01e0 | (FormKind::Data8 as u16),
    DefaultValueString = 0x01e0 | (FormKind::String as u16),
    Friends = 0x01f0 | (FormKind::Block2 as u16),
    Inline = 0x0200 | (FormKind::String as u16),
    IsOptional = 0x0210 | (FormKind::String as u16),
    LowerBoundRef = 0x0220 | (FormKind::Ref as u16),
    LowerBoundData2 = 0x0220 | (FormKind::Data2 as u16),
    LowerBoundData4 = 0x0220 | (FormKind::Data4 as u16),
    LowerBoundData8 = 0x0220 | (FormKind::Data8 as u16),
    Program = 0x0230 | (FormKind::String as u16),
    Private = 0x0240 | (FormKind::String as u16),
    Producer = 0x0250 | (FormKind::String as u16),
    Protected = 0x0260 | (FormKind::String as u16),
    Prototyped = 0x0270 | (FormKind::String as u16),
    Public = 0x0280 | (FormKind::String as u16),
    PureVirtual = 0x0290 | (FormKind::String as u16),
    PureVirtualBlock2 = 0x0290 | (FormKind::Block2 as u16),
    ReturnAddr = 0x02a0 | (FormKind::Block2 as u16),
    Specification = 0x02b0 | (FormKind::Ref as u16),
    StartScope = 0x02c0 | (FormKind::Data4 as u16),
    StrideSize = 0x02e0 | (FormKind::Data4 as u16),
    UpperBoundRef = 0x02f0 | (FormKind::Ref as u16),
    UpperBoundData2 = 0x02f0 | (FormKind::Data2 as u16),
    UpperBoundData4 = 0x02f0 | (FormKind::Data4 as u16),
    UpperBoundData8 = 0x02f0 | (FormKind::Data8 as u16),
    Virtual = 0x0300 | (FormKind::String as u16),
    VirtualBlock2 = 0x0300 | (FormKind::Block2 as u16),
    LoUser = 0x2000,
    HiUser = 0x3ff0,
    // User types
    MwMangled = 0x2000 | (FormKind::String as u16),
    MwRestoreSp = 0x2010 | (FormKind::Block2 as u16),
    MwGlobalRef = 0x2020 | (FormKind::Ref as u16),
    MwGlobalRefByName = 0x2030 | (FormKind::String as u16),
    MwRestoreS0 = 0x2040 | (FormKind::Block2 as u16),
    MwRestoreS1 = 0x2050 | (FormKind::Block2 as u16),
    MwRestoreS2 = 0x2060 | (FormKind::Block2 as u16),
    MwRestoreS3 = 0x2070 | (FormKind::Block2 as u16),
    MwRestoreS4 = 0x2080 | (FormKind::Block2 as u16),
    MwRestoreS5 = 0x2090 | (FormKind::Block2 as u16),
    MwRestoreS6 = 0x20A0 | (FormKind::Block2 as u16),
    MwRestoreS7 = 0x20B0 | (FormKind::Block2 as u16),
    MwRestoreS8 = 0x20C0 | (FormKind::Block2 as u16),
    MwRestoreF20 = 0x20D0 | (FormKind::Block2 as u16),
    MwRestoreF21 = 0x20E0 | (FormKind::Block2 as u16),
    MwRestoreF22 = 0x20F0 | (FormKind::Block2 as u16),
    MwRestoreF23 = 0x2100 | (FormKind::Block2 as u16),
    MwRestoreF24 = 0x2110 | (FormKind::Block2 as u16),
    MwRestoreF25 = 0x2120 | (FormKind::Block2 as u16),
    MwRestoreF26 = 0x2130 | (FormKind::Block2 as u16),
    MwRestoreF27 = 0x2140 | (FormKind::Block2 as u16),
    MwRestoreF28 = 0x2150 | (FormKind::Block2 as u16),
    MwRestoreF29 = 0x2160 | (FormKind::Block2 as u16),
    MwRestoreF30 = 0x2170 | (FormKind::Block2 as u16),
    MwRestoreD20 = 0x2180 | (FormKind::Block2 as u16),
    MwRestoreD21 = 0x2190 | (FormKind::Block2 as u16),
    MwRestoreD22 = 0x21A0 | (FormKind::Block2 as u16),
    MwRestoreD23 = 0x21B0 | (FormKind::Block2 as u16),
    MwRestoreD24 = 0x21C0 | (FormKind::Block2 as u16),
    MwRestoreD25 = 0x21D0 | (FormKind::Block2 as u16),
    MwRestoreD26 = 0x2240 | (FormKind::Block2 as u16),
    MwRestoreD27 = 0x2250 | (FormKind::Block2 as u16),
    MwRestoreD28 = 0x2260 | (FormKind::Block2 as u16),
    MwRestoreD29 = 0x2270 | (FormKind::Block2 as u16),
    MwRestoreD30 = 0x2280 | (FormKind::Block2 as u16),
    MwOverlayId = 0x2290 | (FormKind::Data4 as u16),
    MwOverlayName = 0x22A0 | (FormKind::String as u16),
    MwGlobalRefsBlock = 0x2300 | (FormKind::Block2 as u16),
    MwLocalSpoffset = 0x2310 | (FormKind::Block4 as u16),
    MwMips16 = 0x2330 | (FormKind::String as u16),
    MwDwarf2Location = 0x2340 | (FormKind::Block2 as u16),
    GccSfName = 0x8000 | (FormKind::Data4 as u16), // GccSfName extension (offset into .debug_sfnames)
    GccSfInfo = 0x8010 | (FormKind::Data4 as u16), // GccSfInfo extension (offset into .debug_srcinfo)
    MwPrologueEnd = 0x8040 | (FormKind::Addr as u16),
    MwEpilogueStart = 0x8050 | (FormKind::Addr as u16),
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Address(u32),
    Reference(u32),
    Data2(u16),
    Data4(u32),
    Data8(u64),
    Block(Vec<u8>),
    String(String),
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub kind: AttributeKind,
    pub value: AttributeValue,
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub key: u32,
    pub kind: TagKind,
    pub is_erased: bool,      // Tag was deleted but has been reconstructed
    pub is_erased_root: bool, // Tag is erased and is the root of a tree of erased tags
    pub data_endian: Endian, // Endianness of the tag data (could be different from the address endianness for erased tags)
    pub attributes: Vec<Attribute>,
}

pub type TagMap = BTreeMap<u32, Tag>;
pub type TypedefMap = BTreeMap<u32, Vec<u32>>;

#[derive(Debug, Clone)]
pub struct DwarfInfo {
    pub e: Endian,
    pub tags: TagMap,
}

impl Tag {
    #[inline]
    pub fn attribute(&self, kind: AttributeKind) -> Option<&Attribute> {
        self.attributes.iter().find(|attr| attr.kind == kind)
    }

    #[inline]
    pub fn address_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Address(addr), .. }) => Some(*addr),
            _ => None,
        }
    }

    #[inline]
    pub fn reference_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Reference(addr), .. }) => Some(*addr),
            _ => None,
        }
    }

    #[inline]
    pub fn string_attribute(&self, kind: AttributeKind) -> Option<&String> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::String(str), .. }) => Some(str),
            _ => None,
        }
    }

    #[inline]
    pub fn block_attribute(&self, kind: AttributeKind) -> Option<&[u8]> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Block(vec), .. }) => Some(vec),
            _ => None,
        }
    }

    #[inline]
    pub fn data4_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Data4(value), .. }) => Some(*value),
            _ => None,
        }
    }

    #[inline]
    pub fn data2_attribute(&self, kind: AttributeKind) -> Option<u16> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Data2(value), .. }) => Some(*value),
            _ => None,
        }
    }

    #[inline]
    pub fn type_attribute(&self) -> Option<&Attribute> {
        self.attributes.iter().find(|attr| {
            matches!(
                attr.kind,
                AttributeKind::FundType
                    | AttributeKind::ModFundType
                    | AttributeKind::UserDefType
                    | AttributeKind::ModUDType
            )
        })
    }

    pub fn children<'a>(&self, tags: &'a TagMap) -> Vec<&'a Tag> {
        let sibling = self.next_sibling(tags);
        let mut children = Vec::new();
        let mut child = match self.next_tag(tags, self.is_erased) {
            Some(child) => child,
            None => return children,
        };
        loop {
            if let Some(end) = sibling {
                if child.key == end.key {
                    break;
                }
            }
            if child.kind != TagKind::Padding {
                children.push(child);
            }
            match child.next_sibling(tags) {
                Some(next) => child = next,
                None => break,
            }
        }
        children
    }

    /// Returns the next sibling tag, if any
    pub fn next_sibling<'a>(&self, tags: &'a TagMap) -> Option<&'a Tag> {
        if let Some(key) = self.reference_attribute(AttributeKind::Sibling) {
            tags.get(&key)
        } else {
            self.next_tag(tags, self.is_erased)
        }
    }

    /// Returns the next tag sequentially, if any (skipping erased tags)
    pub fn next_tag<'a>(&self, tags: &'a TagMap, include_erased: bool) -> Option<&'a Tag> {
        tags.range(self.key + 1..)
            .find(|(_, tag)| include_erased || !tag.is_erased)
            .map(|(_, tag)| tag)
    }
}

pub fn read_debug_section<R>(reader: &mut R, e: Endian, include_erased: bool) -> Result<DwarfInfo>
where R: BufRead + Seek + ?Sized {
    let len = {
        let old_pos = reader.stream_position()?;
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(old_pos))?;
        len
    };

    let mut info = DwarfInfo { e, tags: BTreeMap::new() };
    loop {
        let position = reader.stream_position()?;
        if position >= len {
            break;
        }
        let tags = read_tags(reader, e, e, include_erased, false)?;
        for tag in tags {
            info.tags.insert(tag.key, tag);
        }
    }
    Ok(info)
}

#[allow(unused)]
pub fn read_aranges_section<R>(reader: &mut R, e: Endian) -> Result<()>
where R: BufRead + Seek + ?Sized {
    let len = {
        let old_pos = reader.stream_position()?;
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(old_pos))?;
        len
    };

    // let mut tags = BTreeMap::new();
    loop {
        let position = reader.stream_position()?;
        if position >= len {
            break;
        }

        let size = u32::from_reader(reader, e)?;
        let version = u8::from_reader(reader, e)?;
        ensure!(version == 1, "Expected version 1, got {version}");
        let _debug_offs = u32::from_reader(reader, e)?;
        let _debug_size = u32::from_reader(reader, e)?;
        while reader.stream_position()? < position + size as u64 {
            let _address = u32::from_reader(reader, e)?;
            let _length = u32::from_reader(reader, e)?;
        }
    }
    Ok(())
}

fn read_tags<R>(
    reader: &mut R,
    data_endian: Endian,
    addr_endian: Endian,
    include_erased: bool,
    is_erased: bool,
) -> Result<Vec<Tag>>
where
    R: BufRead + Seek + ?Sized,
{
    let mut tags = Vec::new();
    let position = reader.stream_position()?;
    let size = u32::from_reader(reader, data_endian)?;
    if size < 8 {
        // Null entry
        if size > 4 {
            reader.seek(SeekFrom::Current(size as i64 - 4))?;
        }
        tags.push(Tag {
            key: position as u32,
            kind: TagKind::Padding,
            is_erased,
            is_erased_root: false,
            data_endian,
            attributes: Vec::new(),
        });
        return Ok(tags);
    }

    let tag_num = u16::from_reader(reader, data_endian)?;
    let tag = TagKind::try_from(tag_num).context("Unknown DWARF tag type")?;
    if tag == TagKind::Padding {
        if include_erased {
            // Erased entries that have become padding could be either
            // little-endian or big-endian, and we have to guess the length and
            // tag of the first entry. We assume the entry is either a variable
            // or a function, and read until we find the high_pc attribute. Only
            // MwGlobalRef will follow, and these are unlikely to be confused
            // with the length of the next entry.
            let mut attributes = Vec::new();
            let mut is_function = false;

            // Guess endianness based on first attribute
            let data_endian = if is_erased {
                data_endian
            } else {
                // Peek next two bytes
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let attr_tag = u16::from_reader(&mut Cursor::new(&buf), data_endian)?;
                reader.seek(SeekFrom::Current(-2))?;
                match AttributeKind::try_from(attr_tag) {
                    Ok(_) => data_endian,
                    Err(_) => data_endian.flip(),
                }
            };

            while reader.stream_position()? < position + size as u64 {
                // Peek next two bytes
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let attr_tag = u16::from_reader(&mut Cursor::new(&buf), data_endian)?;
                reader.seek(SeekFrom::Current(-2))?;

                if is_function && attr_tag != AttributeKind::MwGlobalRef as u16 {
                    break;
                }

                let attr = read_attribute(reader, data_endian, addr_endian)?;
                if attr.kind == AttributeKind::HighPc {
                    is_function = true;
                }
                attributes.push(attr);
            }
            let kind = if is_function { TagKind::Subroutine } else { TagKind::LocalVariable };
            tags.push(Tag {
                key: position as u32,
                kind,
                is_erased: true,
                is_erased_root: true,
                data_endian,
                attributes,
            });

            // Read the rest of the tags
            while reader.stream_position()? < position + size as u64 {
                for tag in read_tags(reader, data_endian, addr_endian, include_erased, true)? {
                    tags.push(tag);
                }
            }
        } else {
            reader.seek(SeekFrom::Start(position + size as u64))?; // Skip padding
        }
    } else {
        let mut attributes = Vec::new();
        while reader.stream_position()? < position + size as u64 {
            attributes.push(read_attribute(reader, data_endian, addr_endian)?);
        }
        tags.push(Tag {
            key: position as u32,
            kind: tag,
            is_erased,
            is_erased_root: false,
            data_endian,
            attributes,
        });
    }
    Ok(tags)
}

// TODO Shift-JIS?
fn read_string<R>(reader: &mut R) -> Result<String>
where R: BufRead + ?Sized {
    let mut str = String::new();
    let mut buf = [0u8; 1];
    loop {
        reader.read_exact(&mut buf)?;
        if buf[0] == 0 {
            break;
        }
        str.push(buf[0] as char);
    }
    Ok(str)
}

fn read_attribute<R>(
    reader: &mut R,
    data_endian: Endian,
    addr_endian: Endian,
) -> Result<Attribute>
where
    R: BufRead + Seek + ?Sized,
{
    let attr_type = u16::from_reader(reader, data_endian)?;
    let attr = AttributeKind::try_from(attr_type).context("Unknown DWARF attribute type")?;
    let form = FormKind::try_from(attr_type & FORM_MASK).context("Unknown DWARF form type")?;
    let value = match form {
        FormKind::Addr => AttributeValue::Address(u32::from_reader(reader, addr_endian)?),
        FormKind::Ref => AttributeValue::Reference(u32::from_reader(reader, addr_endian)?),
        FormKind::Block2 => {
            let size = u16::from_reader(reader, data_endian)?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Block4 => {
            let size = u32::from_reader(reader, data_endian)?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Data2 => AttributeValue::Data2(u16::from_reader(reader, data_endian)?),
        FormKind::Data4 => AttributeValue::Data4(u32::from_reader(reader, data_endian)?),
        FormKind::Data8 => AttributeValue::Data8(u64::from_reader(reader, data_endian)?),
        FormKind::String => AttributeValue::String(read_string(reader)?),
    };
    Ok(Attribute { kind: attr, value })
}

#[derive(Debug, Clone)]
pub struct ArrayDimension {
    pub index_type: Type,
    pub size: Option<NonZeroU32>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum ArrayOrdering {
    RowMajor = 0,
    // ORD_row_major
    ColMajor = 1, // ORD_col_major
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub element_type: Box<Type>,
    pub dimensions: Vec<ArrayDimension>,
}

#[derive(Debug, Clone)]
pub struct BitData {
    pub bit_size: u32,
    pub bit_offset: u16,
}

#[derive(Debug, Clone)]
pub struct StructureMember {
    pub name: Option<String>,
    pub kind: Type,
    pub offset: u32,
    pub bit: Option<BitData>,
    pub visibility: Visibility,
    pub byte_size: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureKind {
    Struct,
    Class,
}

#[derive(Debug, Clone)]
pub struct StructureType {
    pub kind: StructureKind,
    pub name: Option<String>,
    pub byte_size: Option<u32>,
    pub members: Vec<StructureMember>,
    pub bases: Vec<StructureBase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Protected,
    Public,
}

#[derive(Debug, Clone)]
pub struct StructureBase {
    pub name: Option<String>,
    pub base_type: Type,
    pub offset: u32,
    pub visibility: Option<Visibility>,
    pub virtual_base: bool,
}

#[derive(Debug, Clone)]
pub struct EnumerationMember {
    pub name: String,
    pub value: i32,
}

#[derive(Debug, Clone)]
pub struct EnumerationType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<EnumerationMember>,
}

#[derive(Debug, Clone)]
pub struct UnionType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<StructureMember>,
}

#[derive(Debug, Clone)]
pub struct SubroutineParameter {
    pub name: Option<String>,
    pub kind: Type,
    pub location: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubroutineVariable {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub kind: Type,
    pub location: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubroutineLabel {
    pub name: String,
    pub address: u32,
}

#[derive(Debug, Clone)]
pub struct SubroutineBlock {
    pub name: Option<String>,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
    pub variables: Vec<SubroutineVariable>,
    pub blocks: Vec<SubroutineBlock>,
    pub inlines: Vec<SubroutineType>,
}

#[derive(Debug, Clone)]
pub struct SubroutineType {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub return_type: Type,
    pub parameters: Vec<SubroutineParameter>,
    pub var_args: bool,
    pub prototyped: bool,
    pub references: Vec<u32>,
    pub member_of: Option<u32>,
    pub variables: Vec<SubroutineVariable>,
    pub inline: bool,
    pub virtual_: bool,
    pub local: bool,
    pub labels: Vec<SubroutineLabel>,
    pub blocks: Vec<SubroutineBlock>,
    pub inlines: Vec<SubroutineType>,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PtrToMemberType {
    pub kind: Type,
    pub containing_type: u32,
}

#[derive(Debug, Clone)]
pub enum UserDefinedType {
    Array(ArrayType),
    Structure(StructureType),
    Enumeration(EnumerationType),
    Union(UnionType),
    Subroutine(SubroutineType),
    PtrToMember(PtrToMemberType),
}

#[derive(Debug, Clone)]
pub struct VariableTag {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub kind: Type,
    pub address: Option<u32>,
    pub local: bool,
}

#[derive(Debug, Clone)]
pub struct TypedefTag {
    pub name: String,
    pub kind: Type,
}

#[derive(Debug, Clone)]
pub enum TagType {
    Variable(VariableTag),
    Typedef(TypedefTag),
    UserDefined(UserDefinedType),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum Language {
    C89 = 0x1,
    C = 0x2,
    Ada83 = 0x3,
    CPlusPlus = 0x4,
    Cobol74 = 0x5,
    Cobol85 = 0x6,
    Fortran77 = 0x7,
    Fortran90 = 0x8,
    Pascal83 = 0x9,
    Modula2 = 0xa,
    // MWCC asm extension, emitted by PS2 MWCC asm_r5900_elf.dll
    MwAsm = 0x8000,
}

impl Display for Language {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::C89 => write!(f, "C89"),
            Language::C => write!(f, "C"),
            Language::Ada83 => write!(f, "Ada83"),
            Language::CPlusPlus => write!(f, "C++"),
            Language::Cobol74 => write!(f, "Cobol74"),
            Language::Cobol85 => write!(f, "Cobol85"),
            Language::Fortran77 => write!(f, "Fortran77"),
            Language::Fortran90 => write!(f, "Fortran90"),
            Language::Pascal83 => write!(f, "Pascal83"),
            Language::Modula2 => write!(f, "Modula2"),
            Language::MwAsm => write!(f, "MwAsm"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompileUnit {
    pub name: String,
    pub producer: Option<String>,
    pub comp_dir: Option<String>,
    pub language: Option<Language>,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
    pub gcc_srcfile_name_offset: Option<u32>,
    pub gcc_srcinfo_offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct OverlayBranch {
    pub name: String,
    pub id: u32,
    pub start_address: u32,
    pub end_address: u32,
    pub compile_unit: Option<u32>,
}

impl UserDefinedType {
    pub fn name(&self) -> Option<String> {
        match self {
            UserDefinedType::Array(_) | UserDefinedType::PtrToMember(_) => None,
            UserDefinedType::Structure(t) => t.name.clone(),
            UserDefinedType::Enumeration(t) => t.name.clone(),
            UserDefinedType::Union(t) => t.name.clone(),
            UserDefinedType::Subroutine(t) => t.name.clone(),
        }
    }

    pub fn is_definition(&self) -> bool {
        match self {
            UserDefinedType::Array(_) | UserDefinedType::PtrToMember(_) => false,
            UserDefinedType::Structure(t) => t.name.is_some(),
            UserDefinedType::Enumeration(t) => t.name.is_some(),
            UserDefinedType::Union(t) => t.name.is_some(),
            UserDefinedType::Subroutine(t) => t.name.is_some(),
        }
    }

    pub fn size(&self, info: &DwarfInfo) -> Result<u32> {
        Ok(match self {
            UserDefinedType::Array(t) => {
                let mut size = t.element_type.size(info)?;
                for dim in &t.dimensions {
                    size *= dim.size.map(|u| u.get()).unwrap_or_default();
                }
                size
            }
            UserDefinedType::Structure(t) => match t.byte_size {
                Some(byte_size) => byte_size,
                None => {
                    let mut max_end = 0;
                    for member in &t.members {
                        let size = match member.byte_size {
                            Some(byte_size) => byte_size,
                            None => member.kind.size(info)?,
                        };
                        max_end = max(max_end, member.offset + size);
                    }
                    max_end
                }
            },
            UserDefinedType::Enumeration(t) => t.byte_size,
            UserDefinedType::Union(t) => t.byte_size,
            UserDefinedType::Subroutine(_) => 0,
            UserDefinedType::PtrToMember(_) => 4,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TypeKind {
    Fundamental(FundType),
    UserDefined(u32),
}

#[derive(Debug, Clone)]
pub struct Type {
    pub kind: TypeKind,
    pub modifiers: Vec<Modifier>,
}

impl Type {
    pub fn size(&self, info: &DwarfInfo) -> Result<u32> {
        if self.modifiers.iter().any(|m| {
            matches!(m, Modifier::MwPointerTo | Modifier::PointerTo | Modifier::ReferenceTo)
        }) {
            return Ok(4);
        }
        match self.kind {
            TypeKind::Fundamental(ft) => ft.size(),
            TypeKind::UserDefined(key) => {
                let tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate user defined type {}", key))?;
                let ud_type = ud_type(info, tag)?;
                ud_type.size(info)
            }
        }
    }
}

pub fn apply_modifiers(mut str: TypeString, modifiers: &[Modifier]) -> Result<TypeString> {
    let mut has_pointer = false;
    for &modifier in modifiers.iter().rev() {
        match modifier {
            Modifier::MwPointerTo | Modifier::PointerTo => {
                if !has_pointer && !str.suffix.is_empty() {
                    if str.member.is_empty() {
                        str.prefix.push_str(" (*");
                    } else {
                        write!(str.prefix, " ({}*", str.member)?;
                    }
                    str.suffix.insert(0, ')');
                } else {
                    str.prefix.push_str(" *");
                }
                has_pointer = true;
            }
            Modifier::ReferenceTo => {
                if !has_pointer && !str.suffix.is_empty() {
                    str.prefix.push_str(" (&");
                    str.suffix.insert(0, ')');
                } else {
                    str.prefix.push_str(" &");
                }
                has_pointer = true;
            }
            Modifier::Const => {
                if has_pointer {
                    str.prefix.push_str(" const");
                } else {
                    str.prefix.insert_str(0, "const ");
                }
            }
            Modifier::Volatile => {
                if has_pointer {
                    str.prefix.push_str(" volatile");
                } else {
                    str.prefix.insert_str(0, "volatile ");
                }
            }
        }
    }
    Ok(str)
}

#[derive(Debug, Default, Clone)]
pub struct TypeString {
    pub prefix: String,
    pub suffix: String,
    // TODO: rework this eventually and merge with PTMF handling
    pub member: String,
}

impl Display for TypeString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.member.is_empty() {
            write!(f, "{}{}", self.prefix, self.suffix)?;
        } else {
            // TODO member print likely wrong
            write!(f, "{} {}{}", self.prefix, self.member, self.suffix)?;
        }
        Ok(())
    }
}

pub fn type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &Type,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let str = match t.kind {
        TypeKind::Fundamental(ft) => {
            TypeString { prefix: ft.name()?.to_string(), ..Default::default() }
        }
        TypeKind::UserDefined(key) => {
            if let Some(&td_key) = typedefs.get(&key).and_then(|v| v.first()) {
                let tag = info
                    .tags
                    .get(&td_key)
                    .ok_or_else(|| anyhow!("Failed to locate typedef {}", key))?;
                let td_name = tag
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("typedef without name"))?;
                TypeString { prefix: td_name.clone(), ..Default::default() }
            } else {
                let tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate user defined type {}", key))?;
                ud_type_string(info, typedefs, &ud_type(info, tag)?, true, include_anonymous_def)?
            }
        }
    };
    apply_modifiers(str, &t.modifiers)
}

fn type_name(info: &DwarfInfo, typedefs: &TypedefMap, t: &Type) -> Result<String> {
    Ok(match t.kind {
        TypeKind::Fundamental(ft) => ft.name()?.to_string(),
        TypeKind::UserDefined(key) => {
            if let Some(&td_key) = typedefs.get(&key).and_then(|v| v.first()) {
                info.tags
                    .get(&td_key)
                    .ok_or_else(|| anyhow!("Failed to locate typedef {}", key))?
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("typedef without name"))?
                    .clone()
            } else {
                let tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate user defined type {}", key))?;
                let udt = ud_type(info, tag)?;
                udt.name().ok_or_else(|| anyhow!("User defined type without name"))?
            }
        }
    })
}

fn array_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &ArrayType,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let mut out = type_string(info, typedefs, t.element_type.as_ref(), include_anonymous_def)?;
    for dim in &t.dimensions {
        ensure!(
            matches!(
                dim.index_type.kind,
                TypeKind::Fundamental(FundType::Long | FundType::Integer)
            ),
            "Unsupported array index type '{}'",
            type_string(info, typedefs, &dim.index_type, true)?
        );
        match dim.size {
            None => out.suffix.insert_str(0, "[]"),
            Some(size) => out.suffix = format!("[{}]{}", size, out.suffix),
        };
    }
    Ok(out)
}

fn structure_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &StructureType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            struct_def_string(info, typedefs, t)?
        } else if include_keyword {
            match t.kind {
                StructureKind::Struct => format!("struct {name}"),
                StructureKind::Class => format!("class {name}"),
            }
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        struct_def_string(info, typedefs, t)?
    } else if include_keyword {
        match t.kind {
            StructureKind::Struct => "struct [anonymous]".to_string(),
            StructureKind::Class => "class [anonymous]".to_string(),
        }
    } else {
        match t.kind {
            StructureKind::Struct => "[anonymous struct]".to_string(),
            StructureKind::Class => "[anonymous class]".to_string(),
        }
    };
    Ok(TypeString { prefix, ..Default::default() })
}

fn enumeration_type_string(
    _info: &DwarfInfo,
    _typedefs: &TypedefMap,
    t: &EnumerationType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            enum_def_string(t)?
        } else if include_keyword {
            format!("enum {name}")
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        enum_def_string(t)?
    } else if include_keyword {
        "enum [anonymous]".to_string()
    } else {
        "[anonymous enum]".to_string()
    };
    Ok(TypeString { prefix, ..Default::default() })
}

fn union_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UnionType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            union_def_string(info, typedefs, t)?
        } else if include_keyword {
            format!("union {name}")
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        union_def_string(info, typedefs, t)?
    } else if include_keyword {
        "union [anonymous]".to_string()
    } else {
        "[anonymous union]".to_string()
    };
    Ok(TypeString { prefix, ..Default::default() })
}

pub fn ud_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UserDefinedType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    Ok(match t {
        UserDefinedType::Array(t) => array_type_string(info, typedefs, t, include_anonymous_def)?,
        UserDefinedType::Structure(t) => {
            structure_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Enumeration(t) => {
            enumeration_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Union(t) => {
            union_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Subroutine(t) => subroutine_type_string(info, typedefs, t)?,
        UserDefinedType::PtrToMember(t) => ptr_to_member_type_string(info, typedefs, t)?,
    })
}

fn ptr_to_member_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &PtrToMemberType,
) -> Result<TypeString> {
    let ts = type_string(info, typedefs, &t.kind, true)?;
    let containing_type = info
        .tags
        .get(&t.containing_type)
        .ok_or_else(|| anyhow!("Failed to locate containing type {}", t.containing_type))?;
    let containing_ts =
        ud_type_string(info, typedefs, &ud_type(info, containing_type)?, false, false)?;
    Ok(TypeString {
        prefix: format!("{} ({}::*", ts.prefix, containing_ts.prefix),
        suffix: format!("{}){}", containing_ts.suffix, ts.suffix),
        ..Default::default()
    })
}

pub fn ud_type_def(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UserDefinedType,
    is_erased: bool,
) -> Result<String> {
    match t {
        UserDefinedType::Array(t) => {
            let ts = array_type_string(info, typedefs, t, false)?;
            Ok(format!("// Array: {}{}", ts.prefix, ts.suffix))
        }
        UserDefinedType::Subroutine(t) => Ok(subroutine_def_string(info, typedefs, t, is_erased)?),
        UserDefinedType::Structure(t) => Ok(struct_def_string(info, typedefs, t)?),
        UserDefinedType::Enumeration(t) => Ok(enum_def_string(t)?),
        UserDefinedType::Union(t) => Ok(union_def_string(info, typedefs, t)?),
        UserDefinedType::PtrToMember(t) => {
            let ts = ptr_to_member_type_string(info, typedefs, t)?;
            Ok(format!("// PtrToMember: {}{}", ts.prefix, ts.suffix))
        }
    }
}

pub fn subroutine_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &SubroutineType,
) -> Result<TypeString> {
    let mut out = type_string(info, typedefs, &t.return_type, true)?;
    let mut parameters = String::new();
    if t.parameters.is_empty() {
        if t.var_args {
            parameters = "...".to_string();
        } else if t.prototyped {
            parameters = "void".to_string();
        }
    } else {
        for (idx, parameter) in t.parameters.iter().enumerate() {
            if idx > 0 {
                write!(parameters, ", ")?;
            }
            let ts = type_string(info, typedefs, &parameter.kind, true)?;
            if let Some(name) = &parameter.name {
                write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
            } else {
                write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
            }
            if let Some(location) = &parameter.location {
                write!(parameters, " /* {location} */")?;
            }
        }
        if t.var_args {
            write!(parameters, ", ...")?;
        }
    }
    out.suffix = format!("({}){}", parameters, out.suffix);
    if let Some(member_of) = t.member_of {
        let tag = info
            .tags
            .get(&member_of)
            .ok_or_else(|| anyhow!("Failed to locate member_of tag {}", member_of))?;
        let base_name = tag
            .string_attribute(AttributeKind::Name)
            .ok_or_else(|| anyhow!("member_of tag {} has no name attribute", member_of))?;
        out.member = format!("{base_name}::");
    }
    Ok(out)
}

pub fn subroutine_def_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &SubroutineType,
    is_erased: bool,
) -> Result<String> {
    let mut out = String::new();
    if is_erased {
        out.push_str("// Erased\n");
    } else if let (Some(start), Some(end)) = (t.start_address, t.end_address) {
        writeln!(out, "// Range: {start:#X} -> {end:#X}")?;
    }
    let rt = type_string(info, typedefs, &t.return_type, true)?;
    if t.local {
        out.push_str("static ");
    }
    if t.inline {
        out.push_str("inline ");
    }
    if t.virtual_ {
        out.push_str("virtual ");
    }
    out.push_str(&rt.prefix);
    out.push(' ');

    let mut name_written = false;
    if let Some(member_of) = t.member_of {
        let tag = info
            .tags
            .get(&member_of)
            .ok_or_else(|| anyhow!("Failed to locate member_of tag {}", member_of))?;
        let base_name = tag
            .string_attribute(AttributeKind::Name)
            .ok_or_else(|| anyhow!("member_of tag {} has no name attribute", member_of))?;
        write!(out, "{base_name}::")?;

        // Handle constructors and destructors
        if let Some(name) = t.name.as_ref() {
            if name == "__dt" {
                write!(out, "~{base_name}")?;
                name_written = true;
            } else if name == "__ct" {
                write!(out, "{base_name}")?;
                name_written = true;
            }
        }
    }
    if !name_written {
        if let Some(name) = t.name.as_ref() {
            out.push_str(name);
        }
    }
    let mut parameters = String::new();
    if t.parameters.is_empty() {
        if t.var_args {
            parameters = "...".to_string();
        } else if t.prototyped {
            parameters = "void".to_string();
        }
    } else {
        for (idx, parameter) in t.parameters.iter().enumerate() {
            if idx > 0 {
                write!(parameters, ", ")?;
            }
            let ts = type_string(info, typedefs, &parameter.kind, true)?;
            if let Some(name) = &parameter.name {
                write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
            } else {
                write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
            }
            if let Some(location) = &parameter.location {
                write!(parameters, " /* {location} */")?;
            }
        }
        if t.var_args {
            write!(parameters, ", ...")?;
        }
    }
    write!(out, "({}){} {{", parameters, rt.suffix)?;

    if !t.variables.is_empty() {
        writeln!(out, "\n    // Local variables")?;
        let mut var_out = String::new();
        for variable in &t.variables {
            let ts = type_string(info, typedefs, &variable.kind, true)?;
            write!(
                var_out,
                "{} {}{};",
                ts.prefix,
                variable.name.as_deref().unwrap_or_default(),
                ts.suffix
            )?;
            if let Some(location) = &variable.location {
                write!(var_out, " // {location}")?;
            }
            writeln!(var_out)?;
        }
        write!(out, "{}", indent_all_by(4, var_out))?;
    }

    if !t.references.is_empty() {
        writeln!(out, "\n    // References")?;
        for &reference in &t.references {
            let tag = info
                .tags
                .get(&reference)
                .ok_or_else(|| anyhow!("Failed to locate reference tag {}", reference))?;
            if tag.kind == TagKind::Padding {
                writeln!(out, "    // -> ??? ({reference})")?;
                continue;
            }
            let variable = process_variable_tag(info, tag)?;
            writeln!(out, "    // -> {}", variable_string(info, typedefs, &variable, false)?)?;
        }
    }

    if !t.labels.is_empty() {
        writeln!(out, "\n    // Labels")?;
        for label in &t.labels {
            writeln!(out, "    {}: // {:#X}", label.name, label.address)?;
        }
    }

    if !t.blocks.is_empty() {
        writeln!(out, "\n    // Blocks")?;
        for block in &t.blocks {
            let block_str = subroutine_block_string(info, typedefs, block)?;
            out.push_str(&indent_all_by(4, block_str));
        }
    }

    if !t.inlines.is_empty() {
        writeln!(out, "\n    // Inlines")?;
        for inline in &t.inlines {
            let inline_str = subroutine_def_string(info, typedefs, inline, is_erased)?;
            out.push_str(&indent_all_by(4, inline_str));
        }
    }

    writeln!(out, "}}")?;
    Ok(out)
}

fn subroutine_block_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    block: &SubroutineBlock,
) -> Result<String> {
    let mut out = String::new();
    if let Some(name) = &block.name {
        write!(out, "{name}: ")?;
    } else {
        out.push_str("/* anonymous block */ ");
    }
    out.push_str("{\n");
    if let (Some(start), Some(end)) = (block.start_address, block.end_address) {
        writeln!(out, "    // Range: {start:#X} -> {end:#X}")?;
    }
    let mut var_out = String::new();
    for variable in &block.variables {
        let ts = type_string(info, typedefs, &variable.kind, true)?;
        write!(
            var_out,
            "{} {}{};",
            ts.prefix,
            variable.name.as_deref().unwrap_or_default(),
            ts.suffix
        )?;
        if let Some(location) = &variable.location {
            write!(var_out, " // {location}")?;
        }
        writeln!(var_out)?;
    }
    write!(out, "{}", indent_all_by(4, var_out))?;
    if !block.inlines.is_empty() {
        writeln!(out, "\n    // Inlines")?;
        for inline in &block.inlines {
            let inline_str = subroutine_def_string(info, typedefs, inline, false)?;
            out.push_str(&indent_all_by(4, inline_str));
        }
    }
    for block in &block.blocks {
        let block_str = subroutine_block_string(info, typedefs, block)?;
        out.push_str(&indent_all_by(4, block_str));
    }
    writeln!(out, "}}")?;
    Ok(out)
}

#[derive(Debug, Clone)]
struct AnonUnion {
    offset: u32,
    member_index: usize,
    member_count: usize,
}

#[derive(Debug, Clone)]
struct AnonUnionGroup {
    member_index: usize,
    member_count: usize,
}

fn get_anon_unions(info: &DwarfInfo, members: &[StructureMember]) -> Result<Vec<AnonUnion>> {
    let mut unions = Vec::<AnonUnion>::new();
    let mut offset = u32::MAX;
    'member: for (prev, member) in members.iter().skip(1).enumerate() {
        if let Some(bit) = &member.bit {
            if bit.bit_offset != 0 {
                continue;
            }
        }
        if member.offset <= members[prev].offset && member.offset != offset {
            offset = member.offset;
            for (i, member) in members.iter().enumerate() {
                if member.offset == offset {
                    for anon in &unions {
                        if anon.member_index == i {
                            continue 'member;
                        }
                    }
                    unions.push(AnonUnion { offset, member_index: i, member_count: 0 });
                    break;
                }
            }
        }
    }
    for anon in &mut unions {
        for (i, member) in members.iter().skip(anon.member_index).enumerate() {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset == anon.offset {
                anon.member_count = i;
            }
        }
        let mut max_offset = 0;
        for member in members.iter().skip(anon.member_index).take(anon.member_count + 1) {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            let size =
                if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
            max_offset = max(max_offset, member.offset + size);
        }
        for member in members.iter().skip(anon.member_index + anon.member_count) {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset >= max_offset || member.offset < anon.offset {
                break;
            }
            anon.member_count += 1;
        }
    }
    Ok(unions)
}

fn get_anon_union_groups(members: &[StructureMember], unions: &[AnonUnion]) -> Vec<AnonUnionGroup> {
    let mut groups = Vec::new();
    for anon in unions {
        for (i, member) in
            members.iter().skip(anon.member_index).take(anon.member_count).enumerate()
        {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset == anon.offset {
                let mut group =
                    AnonUnionGroup { member_index: anon.member_index + i, member_count: 1 };

                for member in
                    members.iter().skip(anon.member_index).take(anon.member_count).skip(i + 1)
                {
                    if member.offset == anon.offset {
                        break;
                    }

                    group.member_count += 1;
                }

                if group.member_count > 1 {
                    groups.push(group);
                }
            }
        }
    }
    groups
}

pub fn struct_def_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &StructureType,
) -> Result<String> {
    let mut out = match t.kind {
        StructureKind::Struct => "struct".to_string(),
        StructureKind::Class => "class".to_string(),
    };
    if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            write!(out, " /* {name} */")?;
        } else {
            write!(out, " {name}")?;
        }
    }
    let mut wrote_base = false;
    for base in &t.bases {
        if !wrote_base {
            out.push_str(" : ");
            wrote_base = true;
        } else {
            out.push_str(", ");
        }
        match base.visibility {
            Some(Visibility::Private) => out.push_str("private "),
            Some(Visibility::Protected) => out.push_str("protected "),
            Some(Visibility::Public) => out.push_str("public "),
            None => {}
        }
        if base.virtual_base {
            out.push_str("virtual ");
        }
        if let Some(name) = &base.name {
            out.push_str(name);
        } else {
            out.push_str(&type_name(info, typedefs, &base.base_type)?);
        }
    }
    out.push_str(" {\n");
    if let Some(byte_size) = t.byte_size {
        writeln!(out, "    // total size: {byte_size:#X}")?;
    }
    let mut vis = match t.kind {
        StructureKind::Struct => Visibility::Public,
        StructureKind::Class => Visibility::Private,
    };
    let mut indent = 4;
    let unions = get_anon_unions(info, &t.members)?;
    let groups = get_anon_union_groups(&t.members, &unions);
    let mut in_union = 0;
    let mut in_group = 0;
    for (i, member) in t.members.iter().enumerate() {
        if vis != member.visibility {
            vis = member.visibility;
            match member.visibility {
                Visibility::Private => out.push_str("private:\n"),
                Visibility::Protected => out.push_str("protected:\n"),
                Visibility::Public => out.push_str("public:\n"),
            }
        }
        for anon in &groups {
            if i == anon.member_index + anon.member_count {
                indent -= 4;
                out.push_str(&indent_all_by(indent, "};\n"));
                in_group -= 1;
            }
        }
        for anon in &unions {
            if anon.member_count < 2 {
                continue;
            }
            if i == anon.member_index + anon.member_count {
                indent -= 4;
                out.push_str(&indent_all_by(indent, "};\n"));
                in_union -= 1;
            }
        }
        for anon in &unions {
            if anon.member_count < 2 {
                continue;
            }
            if i == anon.member_index {
                out.push_str(&indent_all_by(indent, "union { // inferred\n"));
                indent += 4;
                in_union += 1;
            }
        }
        for anon in &groups {
            if i == anon.member_index {
                out.push_str(&indent_all_by(indent, "struct { // inferred\n"));
                indent += 4;
                in_group += 1;
            }
        }
        let mut var_out = String::new();
        let ts = type_string(info, typedefs, &member.kind, true)?;
        if let Some(name) = &member.name {
            write!(var_out, "{} {}{}", ts.prefix, name, ts.suffix)?;
        } else {
            write!(var_out, "{}{}", ts.prefix, ts.suffix)?;
        }
        if let Some(bit) = &member.bit {
            write!(var_out, " : {}", bit.bit_size)?;
        }
        let size = if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
        writeln!(var_out, "; // offset {:#X}, size {:#X}", member.offset, size)?;
        out.push_str(&indent_all_by(indent, var_out));
    }
    while in_group > 0 {
        indent -= 4;
        out.push_str(&indent_all_by(indent, "};\n"));
        in_group -= 1;
    }
    while in_union > 0 {
        indent -= 4;
        out.push_str(&indent_all_by(indent, "};\n"));
        in_union -= 1;
    }
    out.push('}');
    Ok(out)
}

pub fn enum_def_string(t: &EnumerationType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => {
            if name.starts_with('@') {
                format!("enum /* {name} */ {{\n")
            } else {
                format!("enum {name} {{\n")
            }
        }
        None => "enum {\n".to_string(),
    };
    for member in t.members.iter() {
        writeln!(out, "    {} = {},", member.name, member.value)?;
    }
    write!(out, "}}")?;
    Ok(out)
}

pub fn union_def_string(info: &DwarfInfo, typedefs: &TypedefMap, t: &UnionType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => {
            if name.starts_with('@') {
                format!("union /* {name} */ {{\n")
            } else {
                format!("union {name} {{\n")
            }
        }
        None => "union {\n".to_string(),
    };
    let mut var_out = String::new();
    for member in t.members.iter() {
        let ts = type_string(info, typedefs, &member.kind, true)?;
        if let Some(name) = &member.name {
            write!(var_out, "{} {}{};", ts.prefix, name, ts.suffix)?;
        } else {
            write!(var_out, "{}{};", ts.prefix, ts.suffix)?;
        }
        let size = if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
        write!(var_out, " // offset {:#X}, size {:#X}", member.offset, size)?;
        writeln!(var_out)?;
    }
    write!(out, "{}", indent_all_by(4, var_out))?;
    write!(out, "}}")?;
    Ok(out)
}

pub fn process_offset(block: &[u8], e: Endian) -> Result<u32> {
    if block.len() == 6 && block[0] == LocationOp::Const as u8 && block[5] == LocationOp::Add as u8
    {
        Ok(u32::from_bytes(*array_ref!(block, 1, 4), e))
    } else {
        Err(anyhow!("Unhandled location data, expected offset"))
    }
}

pub fn process_address(block: &[u8], e: Endian) -> Result<u32> {
    if block.len() == 5 && block[0] == LocationOp::Address as u8 {
        Ok(u32::from_bytes(*array_ref!(block, 1, 4), e))
    } else {
        Err(anyhow!("Unhandled location data, expected address"))
    }
}

pub const REGISTER_NAMES: [&str; 109] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", // 0-7
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", // 8-15
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", // 16-23
    "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31", // 24-31
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", // 32-39
    "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", // 40-47
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", // 48-55
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31", // 56-63
    "mq", "lr", "ctr", "ap", "cr0", "cr1", "cr2", "cr3", // 64-71
    "cr4", "cr5", "cr6", "cr7", "xer", "v0", "v1", "v2", // 72-79
    "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", // 80-87
    "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", // 88-95
    "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", // 96-103
    "v27", "v28", "v29", "v30", "v31", // 104-108
];

pub const fn register_name(reg: u32) -> &'static str {
    if reg < REGISTER_NAMES.len() as u32 {
        REGISTER_NAMES[reg as usize]
    } else {
        "[invalid]"
    }
}

pub fn process_variable_location(block: &[u8], e: Endian) -> Result<String> {
    if block.len() == 5
        && (block[0] == LocationOp::Register as u8
            || block[0] == LocationOp::BaseRegister as u8
            || block[0] == LocationOp::MwFpReg as u8)
    {
        Ok(register_name(u32::from_bytes(*array_ref!(block, 1, 4), e)).to_string())
    } else if block.len() == 5 && block[0] == LocationOp::Address as u8 {
        Ok(format!("@ {:#010X}", u32::from_bytes(*array_ref!(block, 1, 4), e)))
    } else if block.len() == 11
        && block[0] == LocationOp::BaseRegister as u8
        && block[5] == LocationOp::Const as u8
        && block[10] == LocationOp::Add as u8
    {
        Ok(format!(
            "{}+{:#X}",
            register_name(u32::from_bytes(*array_ref!(block, 1, 4), e)),
            u32::from_bytes(*array_ref!(block, 6, 4), e)
        ))
    } else {
        Err(anyhow!("Unhandled location data {:?}, expected variable loc", block))
    }
}

fn process_inheritance_tag(info: &DwarfInfo, tag: &Tag) -> Result<StructureBase> {
    ensure!(tag.kind == TagKind::Inheritance, "{:?} is not an Inheritance tag", tag.kind);

    let mut name = None;
    let mut base_type = None;
    let mut offset = None;
    let mut visibility = None;
    let mut virtual_base = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => base_type = Some(process_type(attr, info.e)?),
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                offset = Some(process_offset(block, info.e)?)
            }
            (AttributeKind::Private, _) => visibility = Some(Visibility::Private),
            (AttributeKind::Protected, _) => visibility = Some(Visibility::Protected),
            (AttributeKind::Public, _) => visibility = Some(Visibility::Public),
            (AttributeKind::Virtual, _) => virtual_base = true,
            _ => {
                bail!("Unhandled Inheritance attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Inheritance child {:?}", child.kind);
    }

    let base_type = base_type.ok_or_else(|| anyhow!("Inheritance without base type: {:?}", tag))?;
    let offset = offset.ok_or_else(|| anyhow!("Inheritance without offset: {:?}", tag))?;
    Ok(StructureBase { name, base_type, offset, visibility, virtual_base })
}

fn process_structure_member_tag(info: &DwarfInfo, tag: &Tag) -> Result<StructureMember> {
    ensure!(tag.kind == TagKind::Member, "{:?} is not a Member tag", tag.kind);

    let mut name = None;
    let mut member_type = None;
    let mut offset = None;
    let mut byte_size = None;
    let mut bit_size = None;
    let mut bit_offset = None;
    let mut visibility = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => member_type = Some(process_type(attr, info.e)?),
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                offset = Some(process_offset(block, info.e)?)
            }
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::BitSize, &AttributeValue::Data4(value)) => bit_size = Some(value),
            (AttributeKind::BitOffset, &AttributeValue::Data2(value)) => bit_offset = Some(value),
            (AttributeKind::Private, _) => visibility = Some(Visibility::Private),
            (AttributeKind::Protected, _) => visibility = Some(Visibility::Protected),
            (AttributeKind::Public, _) => visibility = Some(Visibility::Public),
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled Member attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Member child {:?}", child.kind);
    }

    let kind = member_type.ok_or_else(|| anyhow!("Member without type: {:?}", tag))?;
    let offset = offset.ok_or_else(|| anyhow!("Member without offset: {:?}", tag))?;
    let bit = match (bit_size, bit_offset) {
        (Some(bit_size), Some(bit_offset)) => Some(BitData { bit_size, bit_offset }),
        (None, None) => None,
        _ => bail!("Mismatched bit attributes in Member: {tag:?}"),
    };
    let visibility = visibility.unwrap_or(Visibility::Public);
    Ok(StructureMember { name, kind, offset, bit, visibility, byte_size })
}

fn process_structure_tag(info: &DwarfInfo, tag: &Tag) -> Result<StructureType> {
    ensure!(
        matches!(tag.kind, TagKind::StructureType | TagKind::ClassType),
        "{:?} is not a Structure type tag",
        tag.kind
    );

    let mut name = None;
    let mut byte_size = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled structure attribute {:?}", attr);
            }
        }
    }

    let mut members = Vec::new();
    let mut bases = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::Inheritance => bases.push(process_inheritance_tag(info, child)?),
            TagKind::Member => members.push(process_structure_member_tag(info, child)?),
            TagKind::Typedef => {
                // TODO?
                // info!("Structure {:?} Typedef: {:?}", name, child);
            }
            TagKind::Subroutine | TagKind::GlobalSubroutine => {
                // TODO
            }
            TagKind::GlobalVariable => {
                // TODO
            }
            TagKind::StructureType
            | TagKind::ArrayType
            | TagKind::EnumerationType
            | TagKind::UnionType
            | TagKind::ClassType
            | TagKind::SubroutineType
            | TagKind::PtrToMemberType => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled StructureType child {:?}", kind),
        }
    }

    Ok(StructureType {
        kind: if tag.kind == TagKind::ClassType {
            StructureKind::Class
        } else {
            StructureKind::Struct
        },
        name,
        byte_size,
        members,
        bases,
    })
}

fn process_array_tag(info: &DwarfInfo, tag: &Tag) -> Result<ArrayType> {
    ensure!(tag.kind == TagKind::ArrayType, "{:?} is not an ArrayType tag", tag.kind);

    let mut subscr_data = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::SubscrData, AttributeValue::Block(data)) => {
                subscr_data =
                    Some(process_array_subscript_data(data, info.e).with_context(|| {
                        format!("Failed to process SubscrData for tag: {tag:?}")
                    })?)
            }
            (AttributeKind::Ordering, val) => match val {
                AttributeValue::Data2(d2) => {
                    let order = ArrayOrdering::try_from_primitive(*d2)?;
                    if order == ArrayOrdering::ColMajor {
                        log::warn!("Column Major Ordering in Tag {}, Cannot guarantee array will be correct if original source is in different programming language.", tag.key);
                    }
                }
                _ => bail!("Unhandled ArrayType attribute {:?}", attr),
            },
            _ => {
                bail!("Unhandled ArrayType attribute {:?}", attr)
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled ArrayType child {:?}", child.kind);
    }

    let (element_type, dimensions) =
        subscr_data.ok_or_else(|| anyhow!("ArrayType without SubscrData: {:?}", tag))?;
    Ok(ArrayType { element_type: Box::from(element_type), dimensions })
}

fn process_array_subscript_data(data: &[u8], e: Endian) -> Result<(Type, Vec<ArrayDimension>)> {
    let mut element_type = None;
    let mut dimensions = Vec::new();
    let mut data = data;
    while !data.is_empty() {
        let format = SubscriptFormat::try_from(
            data.first().cloned().ok_or_else(|| anyhow!("Empty SubscrData"))?,
        )
        .context("Unknown array subscript format")?;
        data = &data[1..];
        match format {
            SubscriptFormat::FundTypeConstConst => {
                let index_type = FundType::try_from(u16::from_bytes(data[..2].try_into()?, e))
                    .context("Invalid fundamental type ID")?;
                let low_bound = u32::from_bytes(data[2..6].try_into()?, e);
                ensure!(low_bound == 0, "Invalid array low bound {low_bound}, expected 0");
                let high_bound = u32::from_bytes(data[6..10].try_into()?, e);
                data = &data[10..];
                dimensions.push(ArrayDimension {
                    index_type: Type { kind: TypeKind::Fundamental(index_type), modifiers: vec![] },
                    // u32::MAX will wrap to 0, meaning unbounded
                    size: NonZeroU32::new(high_bound.wrapping_add(1)),
                });
            }
            SubscriptFormat::FundTypeConstLocation => {
                let index_type = FundType::try_from(u16::from_bytes(*array_ref!(data, 0, 2), e))
                    .context("Invalid fundamental type ID")?;
                let low_bound = u32::from_bytes(*array_ref!(data, 2, 4), e);
                ensure!(low_bound == 0, "Invalid array low bound {low_bound}, expected 0");
                let size = u16::from_bytes(*array_ref!(data, 6, 2), e);
                let (block, remain) = data[8..].split_at(size as usize);
                let location = if block.is_empty() { 0 } else { process_offset(block, e)? };
                data = remain;
                dimensions.push(ArrayDimension {
                    index_type: Type { kind: TypeKind::Fundamental(index_type), modifiers: vec![] },
                    size: NonZeroU32::new(location),
                });
            }
            SubscriptFormat::ElementType => {
                let mut cursor = Cursor::new(data);
                // TODO: is this the right endianness to use for erased tags?
                let type_attr = read_attribute(&mut cursor, e, e)?;
                element_type = Some(process_type(&type_attr, e)?);
                data = &data[cursor.position() as usize..];
            }
            _ => bail!("Unhandled subscript format type {:?}", format),
        }
    }
    let element_type = element_type.ok_or_else(|| anyhow!("ArrayType without ElementType"))?;
    Ok((element_type, dimensions))
}

fn process_enumeration_tag(info: &DwarfInfo, tag: &Tag) -> Result<EnumerationType> {
    ensure!(tag.kind == TagKind::EnumerationType, "{:?} is not an EnumerationType tag", tag.kind);

    let mut name = None;
    let mut byte_size = None;
    let mut members = Vec::new();
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::ElementList, AttributeValue::Block(data)) => {
                let mut cursor = Cursor::new(data);
                while cursor.position() < data.len() as u64 {
                    let value = i32::from_reader(&mut cursor, info.e)?;
                    let name = read_string(&mut cursor)?;
                    members.push(EnumerationMember { name, value });
                }
            }
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled EnumerationType attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled EnumerationType child {:?}", child.kind);
    }

    let byte_size =
        byte_size.ok_or_else(|| anyhow!("EnumerationType without ByteSize: {:?}", tag))?;
    Ok(EnumerationType { name, byte_size, members })
}

fn process_union_tag(info: &DwarfInfo, tag: &Tag) -> Result<UnionType> {
    ensure!(tag.kind == TagKind::UnionType, "{:?} is not a UnionType tag", tag.kind);

    let mut name = None;
    let mut byte_size = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled UnionType attribute {:?}", attr);
            }
        }
    }

    let mut members = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::Member => members.push(process_structure_member_tag(info, child)?),
            TagKind::StructureType
            | TagKind::ArrayType
            | TagKind::EnumerationType
            | TagKind::UnionType
            | TagKind::ClassType
            | TagKind::SubroutineType
            | TagKind::PtrToMemberType
            | TagKind::Typedef => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled UnionType child {:?}", kind),
        }
    }

    let byte_size = byte_size.ok_or_else(|| anyhow!("UnionType without ByteSize: {:?}", tag))?;
    Ok(UnionType { name, byte_size, members })
}

fn process_subroutine_tag(info: &DwarfInfo, tag: &Tag) -> Result<SubroutineType> {
    ensure!(
        matches!(
            tag.kind,
            TagKind::SubroutineType
                | TagKind::GlobalSubroutine
                | TagKind::Subroutine
                | TagKind::InlinedSubroutine
        ),
        "{:?} is not a Subroutine tag",
        tag.kind
    );

    let mut name = None;
    let mut mangled_name = None;
    let mut return_type = None;
    let mut prototyped = false;
    let mut parameters = Vec::new();
    let mut var_args = false;
    let mut references = Vec::new();
    let mut member_of = None;
    let mut inline = false;
    let mut start_address = None;
    let mut end_address = None;
    let mut virtual_ = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => return_type = Some(process_type(attr, info.e)?),
            (AttributeKind::Prototyped, _) => prototyped = true,
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => {
                start_address = Some(addr);
            }
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => {
                end_address = Some(addr);
            }
            (AttributeKind::MwGlobalRef, &AttributeValue::Reference(key)) => {
                references.push(key);
            }
            (AttributeKind::MwGlobalRefsBlock, AttributeValue::Block(_)) => {
                // Global references block
            }
            (AttributeKind::ReturnAddr, AttributeValue::Block(_block)) => {
                // let location = process_variable_location(block)?;
                // info!("ReturnAddr: {}", location);
            }
            (AttributeKind::Member, &AttributeValue::Reference(key)) => {
                member_of = Some(key);
            }
            (AttributeKind::MwPrologueEnd, &AttributeValue::Address(_addr)) => {
                // Prologue end
            }
            (AttributeKind::MwEpilogueStart, &AttributeValue::Address(_addr)) => {
                // Epilogue start
            }
            (
                AttributeKind::MwRestoreSp
                | AttributeKind::MwRestoreS0
                | AttributeKind::MwRestoreS1
                | AttributeKind::MwRestoreS2
                | AttributeKind::MwRestoreS3
                | AttributeKind::MwRestoreS4
                | AttributeKind::MwRestoreS5
                | AttributeKind::MwRestoreS6
                | AttributeKind::MwRestoreS7
                | AttributeKind::MwRestoreS8
                | AttributeKind::MwRestoreF20
                | AttributeKind::MwRestoreF21
                | AttributeKind::MwRestoreF22
                | AttributeKind::MwRestoreF23
                | AttributeKind::MwRestoreF24
                | AttributeKind::MwRestoreF25
                | AttributeKind::MwRestoreF26
                | AttributeKind::MwRestoreF27
                | AttributeKind::MwRestoreF28
                | AttributeKind::MwRestoreF29
                | AttributeKind::MwRestoreF30,
                AttributeValue::Block(_),
            ) => {
                // Restore register
            }
            (AttributeKind::Inline, _) => inline = true,
            (AttributeKind::Virtual, _) => virtual_ = true,
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = process_subroutine_tag(info, spec_tag)?;
                name = name.or(spec.name);
                mangled_name = mangled_name.or(spec.mangled_name);
                return_type = return_type.or(Some(spec.return_type));
                prototyped = prototyped || spec.prototyped;
                parameters.extend(spec.parameters);
                var_args = var_args || spec.var_args;
                references.extend(spec.references);
                member_of = member_of.or(spec.member_of);
                inline = inline || spec.inline;
                virtual_ = virtual_ || spec.virtual_;
            }
            _ => {
                bail!("Unhandled SubroutineType attribute {:?}", attr);
            }
        }
    }

    let mut variables = Vec::new();
    let mut labels = Vec::new();
    let mut blocks = Vec::new();
    let mut inlines = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::FormalParameter => {
                parameters.push(process_subroutine_parameter_tag(info, child)?)
            }
            TagKind::UnspecifiedParameters => var_args = true,
            TagKind::LocalVariable => variables.push(process_local_variable_tag(info, child)?),
            TagKind::GlobalVariable => {
                // TODO GlobalVariable refs?
            }
            TagKind::Label => labels.push(process_subroutine_label_tag(info, child)?),
            TagKind::LexicalBlock => {
                if let Some(block) = process_subroutine_block_tag(info, child)? {
                    blocks.push(block);
                }
            }
            TagKind::InlinedSubroutine => inlines.push(process_subroutine_tag(info, child)?),
            TagKind::StructureType
            | TagKind::ArrayType
            | TagKind::EnumerationType
            | TagKind::UnionType
            | TagKind::ClassType
            | TagKind::SubroutineType
            | TagKind::PtrToMemberType
            | TagKind::Typedef => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled SubroutineType child {:?}", kind),
        }
    }

    let return_type = return_type
        .unwrap_or_else(|| Type { kind: TypeKind::Fundamental(FundType::Void), modifiers: vec![] });
    let local = tag.kind == TagKind::Subroutine;
    Ok(SubroutineType {
        name,
        mangled_name,
        return_type,
        parameters,
        var_args,
        prototyped,
        references,
        member_of,
        variables,
        inline,
        virtual_,
        local,
        labels,
        blocks,
        inlines,
        start_address,
        end_address,
    })
}

fn process_subroutine_label_tag(info: &DwarfInfo, tag: &Tag) -> Result<SubroutineLabel> {
    ensure!(tag.kind == TagKind::Label, "{:?} is not a Label tag", tag.kind);

    let mut name = None;
    let mut address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => address = Some(addr),
            _ => bail!("Unhandled Label attribute {:?}", attr),
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Label child {:?}", child.kind);
    }

    let name = name.ok_or_else(|| anyhow!("Label without name: {:?}", tag))?;
    let address = address.ok_or_else(|| anyhow!("Label without address: {:?}", tag))?;
    Ok(SubroutineLabel { name, address })
}

fn process_subroutine_block_tag(info: &DwarfInfo, tag: &Tag) -> Result<Option<SubroutineBlock>> {
    ensure!(tag.kind == TagKind::LexicalBlock, "{:?} is not a LexicalBlock tag", tag.kind);

    let mut name = None;
    let mut start_address = None;
    let mut end_address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            _ => bail!("Unhandled Label attribute {:?}", attr),
        }
    }

    let mut variables = Vec::new();
    let mut blocks = Vec::new();
    let mut inlines = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::LocalVariable => variables.push(process_local_variable_tag(info, child)?),
            TagKind::GlobalVariable => {
                // TODO GlobalVariable refs?
            }
            TagKind::LexicalBlock => {
                if let Some(block) = process_subroutine_block_tag(info, child)? {
                    blocks.push(block);
                }
            }
            TagKind::InlinedSubroutine => {
                inlines.push(process_subroutine_tag(info, child)?);
            }
            TagKind::StructureType
            | TagKind::ArrayType
            | TagKind::EnumerationType
            | TagKind::UnionType
            | TagKind::ClassType
            | TagKind::SubroutineType
            | TagKind::PtrToMemberType => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled LexicalBlock child {:?}", kind),
        }
    }

    Ok(Some(SubroutineBlock { name, start_address, end_address, variables, blocks, inlines }))
}

fn process_subroutine_parameter_tag(info: &DwarfInfo, tag: &Tag) -> Result<SubroutineParameter> {
    ensure!(tag.kind == TagKind::FormalParameter, "{:?} is not a FormalParameter tag", tag.kind);

    let mut name = None;
    let mut kind = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => kind = Some(process_type(attr, info.e)?),
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::ConstValueBlock2 | AttributeKind::ConstValueBlock4, _) => {
                // TODO?
                // info!("ConstValueBlock: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = process_subroutine_parameter_tag(info, spec_tag)?;
                name = name.or(spec.name);
                kind = kind.or(Some(spec.kind));
                location = location.or(spec.location);
            }
            _ => bail!("Unhandled SubroutineParameter attribute {:?}", attr),
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled SubroutineParameter child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("SubroutineParameter without type: {:?}", tag))?;
    Ok(SubroutineParameter { name, kind, location })
}

fn process_local_variable_tag(info: &DwarfInfo, tag: &Tag) -> Result<SubroutineVariable> {
    ensure!(tag.kind == TagKind::LocalVariable, "{:?} is not a LocalVariable tag", tag.kind);

    let mut mangled_name = None;
    let mut name = None;
    let mut kind = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => kind = Some(process_type(attr, info.e)?),
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = process_local_variable_tag(info, spec_tag)?;
                name = name.or(spec.name);
                kind = kind.or(Some(spec.kind));
                location = location.or(spec.location);
            }
            _ => {
                bail!("Unhandled LocalVariable attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled LocalVariable child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("LocalVariable without type: {:?}", tag))?;
    Ok(SubroutineVariable { name, mangled_name, kind, location })
}

fn process_ptr_to_member_tag(info: &DwarfInfo, tag: &Tag) -> Result<PtrToMemberType> {
    ensure!(tag.kind == TagKind::PtrToMemberType, "{:?} is not a PtrToMemberType tag", tag.kind);

    let mut kind = None;
    let mut containing_type = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => kind = Some(process_type(attr, info.e)?),
            (AttributeKind::ContainingType, &AttributeValue::Reference(key)) => {
                containing_type = Some(key)
            }
            _ => {
                bail!("Unhandled PtrToMemberType attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled PtrToMemberType child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("PtrToMemberType without type: {:?}", tag))?;
    let containing_type = containing_type
        .ok_or_else(|| anyhow!("PtrToMemberType without containing type: {:?}", tag))?;
    Ok(PtrToMemberType { kind, containing_type })
}

pub fn ud_type(info: &DwarfInfo, tag: &Tag) -> Result<UserDefinedType> {
    match tag.kind {
        TagKind::ArrayType => Ok(UserDefinedType::Array(process_array_tag(info, tag)?)),
        TagKind::StructureType | TagKind::ClassType => {
            Ok(UserDefinedType::Structure(process_structure_tag(info, tag)?))
        }
        TagKind::EnumerationType => {
            Ok(UserDefinedType::Enumeration(process_enumeration_tag(info, tag)?))
        }
        TagKind::UnionType => Ok(UserDefinedType::Union(process_union_tag(info, tag)?)),
        TagKind::SubroutineType | TagKind::GlobalSubroutine | TagKind::Subroutine => {
            Ok(UserDefinedType::Subroutine(process_subroutine_tag(info, tag)?))
        }
        TagKind::PtrToMemberType => {
            Ok(UserDefinedType::PtrToMember(process_ptr_to_member_tag(info, tag)?))
        }
        kind => Err(anyhow!("Unhandled user defined type {kind:?}")),
    }
}

pub fn process_modifiers(block: &[u8]) -> Result<Vec<Modifier>> {
    let mut out = Vec::with_capacity(block.len());
    for &b in block {
        out.push(Modifier::parse_int(b)?);
    }
    Ok(out)
}

pub fn process_type(attr: &Attribute, e: Endian) -> Result<Type> {
    match (attr.kind, &attr.value) {
        (AttributeKind::FundType, &AttributeValue::Data2(type_id)) => {
            let fund_type = FundType::parse_int(type_id)
                .with_context(|| format!("Invalid fundamental type ID '{type_id:04X}'"))?;
            Ok(Type { kind: TypeKind::Fundamental(fund_type), modifiers: vec![] })
        }
        (AttributeKind::ModFundType, AttributeValue::Block(ops)) => {
            let type_id = u16::from_bytes(ops[ops.len() - 2..].try_into()?, e);
            let fund_type = FundType::parse_int(type_id)
                .with_context(|| format!("Invalid fundamental type ID '{type_id:04X}'"))?;
            let modifiers = process_modifiers(&ops[..ops.len() - 2])?;
            Ok(Type { kind: TypeKind::Fundamental(fund_type), modifiers })
        }
        (AttributeKind::UserDefType, &AttributeValue::Reference(key)) => {
            Ok(Type { kind: TypeKind::UserDefined(key), modifiers: vec![] })
        }
        (AttributeKind::ModUDType, AttributeValue::Block(ops)) => {
            let ud_ref = u32::from_bytes(ops[ops.len() - 4..].try_into()?, e);
            let modifiers = process_modifiers(&ops[..ops.len() - 4])?;
            Ok(Type { kind: TypeKind::UserDefined(ud_ref), modifiers })
        }
        _ => Err(anyhow!("Invalid type attribute {:?}", attr)),
    }
}

pub fn process_compile_unit(tag: &Tag) -> Result<CompileUnit> {
    ensure!(tag.kind == TagKind::CompileUnit, "{:?} is not a CompileUnit tag", tag.kind);

    let mut name = None;
    let mut producer = None;
    let mut comp_dir = None;
    let mut language = None;
    let mut start_address = None;
    let mut end_address = None;
    let mut gcc_srcfile_name_offset = None;
    let mut gcc_srcinfo_offset = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::Producer, AttributeValue::String(s)) => producer = Some(s.clone()),
            (AttributeKind::CompDir, AttributeValue::String(s)) => comp_dir = Some(s.clone()),
            (AttributeKind::Language, &AttributeValue::Data4(value)) => {
                language = Some(Language::try_from_primitive(value)?)
            }
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            (AttributeKind::StmtList, AttributeValue::Data4(_value)) => {
                // TODO .line support
            }

            (AttributeKind::GccSfName, &AttributeValue::Data4(value)) => {
                gcc_srcfile_name_offset = Some(value)
            }
            (AttributeKind::GccSfInfo, &AttributeValue::Data4(value)) => {
                gcc_srcinfo_offset = Some(value)
            }
            _ => {
                bail!("Unhandled CompileUnit attribute {:?}", attr);
            }
        }
    }

    let name = name.ok_or_else(|| anyhow!("CompileUnit without Name: {:?}", tag))?;
    Ok(CompileUnit {
        name,
        producer,
        comp_dir,
        language,
        start_address,
        end_address,
        gcc_srcfile_name_offset,
        gcc_srcinfo_offset,
    })
}

pub fn process_overlay_branch(tag: &Tag) -> Result<OverlayBranch> {
    ensure!(tag.kind == TagKind::MwOverlayBranch, "{:?} is not an OverlayBranch tag", tag.kind);

    let mut name = None;
    let mut id = None;
    let mut start_address = None;
    let mut end_address = None;
    let mut compile_unit = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Member, AttributeValue::Reference(addr)) => compile_unit = Some(*addr),
            (AttributeKind::MwOverlayName, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwOverlayId, AttributeValue::Data4(value)) => id = Some(*value),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            (AttributeKind::Name, AttributeValue::String(_s)) => {
                // TODO
            }
            _ => bail!("Unhandled OverlayBranch attribute {:?}", attr),
        }
    }

    let name = name.ok_or_else(|| anyhow!("OverlayBranch without Name: {:?}", tag))?;
    let id = id.ok_or_else(|| anyhow!("OverlayBranch without Id: {:?}", tag))?;
    let start_address =
        start_address.ok_or_else(|| anyhow!("OverlayBranch without LowPc: {:?}", tag))?;
    let end_address =
        end_address.ok_or_else(|| anyhow!("OverlayBranch without HighPc: {:?}", tag))?;
    Ok(OverlayBranch { name, id, start_address, end_address, compile_unit })
}

pub fn process_cu_tag(info: &DwarfInfo, tag: &Tag) -> Result<TagType> {
    match tag.kind {
        TagKind::Typedef => Ok(TagType::Typedef(process_typedef_tag(info, tag)?)),
        TagKind::GlobalVariable | TagKind::LocalVariable => {
            Ok(TagType::Variable(process_variable_tag(info, tag)?))
        }
        TagKind::StructureType
        | TagKind::ArrayType
        | TagKind::EnumerationType
        | TagKind::UnionType
        | TagKind::ClassType
        | TagKind::SubroutineType
        | TagKind::GlobalSubroutine
        | TagKind::Subroutine
        | TagKind::PtrToMemberType => Ok(TagType::UserDefined(ud_type(info, tag)?)),
        kind => Err(anyhow!("Unhandled root tag type {:?}", kind)),
    }
}

/// Logic to skip uninteresting tags
pub fn should_skip_tag(tag_type: &TagType, is_erased: bool) -> bool {
    match tag_type {
        TagType::Variable(_) => is_erased,
        TagType::Typedef(_) => false,
        TagType::UserDefined(t) => !t.is_definition(),
    }
}

pub fn tag_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    tag_type: &TagType,
    is_erased: bool,
) -> Result<String> {
    match tag_type {
        TagType::Typedef(t) => typedef_string(info, typedefs, t),
        TagType::Variable(v) => variable_string(info, typedefs, v, true),
        TagType::UserDefined(ud) => {
            let ud_str = ud_type_def(info, typedefs, ud, is_erased)?;
            match ud {
                UserDefinedType::Structure(_)
                | UserDefinedType::Enumeration(_)
                | UserDefinedType::Union(_) => Ok(format!("{ud_str};")),
                _ => Ok(ud_str),
            }
        }
    }
}

fn typedef_string(info: &DwarfInfo, typedefs: &TypedefMap, typedef: &TypedefTag) -> Result<String> {
    let ts = type_string(info, typedefs, &typedef.kind, true)?;
    Ok(format!("typedef {} {}{};", ts.prefix, typedef.name, ts.suffix))
}

fn variable_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    variable: &VariableTag,
    include_extra: bool,
) -> Result<String> {
    let ts = type_string(info, typedefs, &variable.kind, include_extra)?;
    let mut out = if variable.local { "static ".to_string() } else { String::new() };
    out.push_str(&ts.prefix);
    out.push(' ');
    out.push_str(variable.name.as_deref().unwrap_or("[unknown]"));
    out.push_str(&ts.suffix);
    out.push(';');
    if include_extra {
        let size = variable.kind.size(info)?;
        out.push_str(&format!(" // size: {size:#X}"));
        if let Some(addr) = variable.address {
            out.push_str(&format!(", address: {addr:#X}"));
        }
    }
    Ok(out)
}

fn process_typedef_tag(info: &DwarfInfo, tag: &Tag) -> Result<TypedefTag> {
    ensure!(tag.kind == TagKind::Typedef, "{:?} is not a typedef tag", tag.kind);

    let mut name = None;
    let mut kind = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => kind = Some(process_type(attr, info.e)?),
            _ => {
                bail!("Unhandled Typedef attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Typedef child {:?}", child.kind);
    }

    let name = name.ok_or_else(|| anyhow!("Typedef without Name: {:?}", tag))?;
    let kind = kind.ok_or_else(|| anyhow!("Typedef without Type: {:?}", tag))?;
    Ok(TypedefTag { name, kind })
}

fn process_variable_tag(info: &DwarfInfo, tag: &Tag) -> Result<VariableTag> {
    ensure!(
        matches!(tag.kind, TagKind::GlobalVariable | TagKind::LocalVariable),
        "{:?} is not a variable tag",
        tag.kind
    );

    let mut name = None;
    let mut mangled_name = None;
    let mut kind = None;
    let mut address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => kind = Some(process_type(attr, info.e)?),
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                address = Some(process_address(block, info.e)?)
            }
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled Variable attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Variable child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("Variable without Type: {:?}", tag))?;
    let local = tag.kind == TagKind::LocalVariable;
    Ok(VariableTag { name, mangled_name, kind, address, local })
}
