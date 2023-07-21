use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fmt::{Display, Formatter, Write},
    io::{BufRead, Cursor, Seek, SeekFrom},
    num::NonZeroU32,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use byteorder::{BigEndian, ReadBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};

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
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum FundType {
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
}

impl FundType {
    fn size(self) -> Result<u32> {
        Ok(match self {
            FundType::Char | FundType::SignedChar | FundType::UnsignedChar | FundType::Boolean => 1,
            FundType::Short | FundType::SignedShort | FundType::UnsignedShort => 2,
            FundType::Integer | FundType::SignedInteger | FundType::UnsignedInteger => 4,
            FundType::Long
            | FundType::SignedLong
            | FundType::UnsignedLong
            | FundType::Pointer
            | FundType::Float => 4,
            FundType::DblPrecFloat
            | FundType::LongLong
            | FundType::SignedLongLong
            | FundType::UnsignedLongLong => 8,
            FundType::Void => 0,
            FundType::ExtPrecFloat
            | FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Modifier {
    PointerTo = 0x01,
    ReferenceTo = 0x02,
    Const = 0x03,
    Volatile = 0x04,
    // User types
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
    ReturnAddr = 0x02a0 | (FormKind::Block2 as u16),
    Specification = 0x02b0 | (FormKind::Ref as u16),
    StartScope = 0x02c0 | (FormKind::Data4 as u16),
    StrideSize = 0x02e0 | (FormKind::Data4 as u16),
    UpperBoundRef = 0x02f0 | (FormKind::Ref as u16),
    UpperBoundData2 = 0x02f0 | (FormKind::Data2 as u16),
    UpperBoundData4 = 0x02f0 | (FormKind::Data4 as u16),
    UpperBoundData8 = 0x02f0 | (FormKind::Data8 as u16),
    Virtual = 0x0300 | (FormKind::String as u16),
    LoUser = 0x2000,
    HiUser = 0x3ff0,
    // User types
    Unknown200 = 0x2000 | (FormKind::String as u16),
    MwVariableRef = 0x2020 | (FormKind::Ref as u16),
    Unknown234 = 0x2340 | (FormKind::Block2 as u16),
    Unknown800 = 0x8000 | (FormKind::Data4 as u16),
    Unknown801 = 0x8010 | (FormKind::Data4 as u16),
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
    pub attributes: Vec<Attribute>,
}

pub type TagMap = BTreeMap<u32, Tag>;
pub type TypedefMap = BTreeMap<u32, Vec<u32>>;

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
        let (_, mut child) = match tags.range(self.key + 1..).next() {
            Some(child) => child,
            None => return children,
        };
        if child.kind == TagKind::Padding {
            return children;
        }
        loop {
            if let Some(end) = sibling {
                if child.key == end.key {
                    break;
                }
            }
            children.push(child);
            match child.next_sibling(tags) {
                Some(next) => child = next,
                None => break,
            }
        }
        children
    }

    pub fn next_sibling<'a>(&self, tags: &'a TagMap) -> Option<&'a Tag> {
        if let Some(key) = self.reference_attribute(AttributeKind::Sibling) {
            if let Some(next) = tags.get(&key) {
                if next.kind != TagKind::Padding {
                    return Some(next);
                }
            }
        }
        None
    }
}

pub fn read_debug_section<R: BufRead + Seek>(reader: &mut R) -> Result<TagMap> {
    let len = {
        let old_pos = reader.stream_position()?;
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(old_pos))?;
        len
    };

    let mut tags = BTreeMap::new();
    loop {
        let position = reader.stream_position()?;
        if position >= len {
            break;
        }
        let tag = read_tag(reader)?;
        tags.insert(position as u32, tag);
    }
    Ok(tags)
}

#[allow(unused)]
pub fn read_aranges_section<R: BufRead + Seek>(reader: &mut R) -> Result<()> {
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

        let size = reader.read_u32::<BigEndian>()?;
        let version = reader.read_u8()?;
        ensure!(version == 1, "Expected version 1, got {version}");
        let _debug_offs = reader.read_u32::<BigEndian>()?;
        let _debug_size = reader.read_u32::<BigEndian>()?;
        while reader.stream_position()? < position + size as u64 {
            let _address = reader.read_u32::<BigEndian>()?;
            let _length = reader.read_u32::<BigEndian>()?;
        }
    }
    Ok(())
}

fn read_tag<R: BufRead + Seek>(reader: &mut R) -> Result<Tag> {
    let position = reader.stream_position()?;
    let size = reader.read_u32::<BigEndian>()?;
    if size < 8 {
        if size > 4 {
            reader.seek(SeekFrom::Current(size as i64 - 4))?;
        }
        return Ok(Tag { key: position as u32, kind: TagKind::Padding, attributes: vec![] });
    }

    let tag =
        TagKind::try_from(reader.read_u16::<BigEndian>()?).context("Unknown DWARF tag type")?;
    let mut attributes = Vec::new();
    while reader.stream_position()? < position + size as u64 {
        attributes.push(read_attribute(reader)?);
    }
    Ok(Tag { key: position as u32, kind: tag, attributes })
}

// TODO Shift-JIS?
fn read_string<R: BufRead>(reader: &mut R) -> Result<String> {
    let mut str = String::new();
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        str.push(byte as char);
    }
    Ok(str)
}

fn read_attribute<R: BufRead + Seek>(reader: &mut R) -> Result<Attribute> {
    let attr_type = reader.read_u16::<BigEndian>()?;
    let attr = AttributeKind::try_from(attr_type).context("Unknown DWARF attribute type")?;
    let form = FormKind::try_from(attr_type & FORM_MASK).context("Unknown DWARF form type")?;
    let value = match form {
        FormKind::Addr => AttributeValue::Address(reader.read_u32::<BigEndian>()?),
        FormKind::Ref => AttributeValue::Reference(reader.read_u32::<BigEndian>()?),
        FormKind::Block2 => {
            let size = reader.read_u16::<BigEndian>()?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Block4 => {
            let size = reader.read_u32::<BigEndian>()?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Data2 => AttributeValue::Data2(reader.read_u16::<BigEndian>()?),
        FormKind::Data4 => AttributeValue::Data4(reader.read_u32::<BigEndian>()?),
        FormKind::Data8 => AttributeValue::Data8(reader.read_u64::<BigEndian>()?),
        FormKind::String => AttributeValue::String(read_string(reader)?),
    };
    Ok(Attribute { kind: attr, value })
}

#[derive(Debug, Clone)]
pub struct ArrayDimension {
    pub index_type: Type,
    pub size: Option<NonZeroU32>,
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub element_type: Box<Type>,
    pub dimensions: Vec<ArrayDimension>,
}

#[derive(Debug, Clone)]
pub struct BitData {
    pub byte_size: u32,
    pub bit_size: u32,
    pub bit_offset: u16,
}

#[derive(Debug, Clone)]
pub struct StructureMember {
    pub name: String,
    pub kind: Type,
    pub offset: u32,
    pub bit: Option<BitData>,
}

#[derive(Debug, Clone)]
pub struct StructureType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<StructureMember>,
}

#[derive(Debug, Clone)]
pub struct EnumerationMember {
    pub name: String,
    pub value: u32,
}

#[derive(Debug, Clone)]
pub struct EnumerationType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<EnumerationMember>,
}

#[derive(Debug, Clone)]
pub struct UnionMember {
    pub name: String,
    pub kind: Type,
}

#[derive(Debug, Clone)]
pub struct UnionType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<UnionMember>,
}

#[derive(Debug, Clone)]
pub struct SubroutineParameter {
    pub name: Option<String>,
    pub kind: Type,
}

#[derive(Debug, Clone)]
pub struct SubroutineType {
    pub return_type: Type,
    pub parameters: Vec<SubroutineParameter>,
    pub var_args: bool,
    pub prototyped: bool,
}

#[derive(Debug, Clone)]
pub enum UserDefinedType {
    Array(ArrayType),
    Structure(StructureType),
    Enumeration(EnumerationType),
    Union(UnionType),
    Subroutine(SubroutineType),
}

impl UserDefinedType {
    pub fn is_definition(&self) -> bool {
        match self {
            UserDefinedType::Array(_) | UserDefinedType::Subroutine(_) => false,
            UserDefinedType::Structure(t) => t.name.is_some(),
            UserDefinedType::Enumeration(t) => t.name.is_some(),
            UserDefinedType::Union(t) => t.name.is_some(),
        }
    }

    pub fn size(&self, tags: &TagMap) -> Result<u32> {
        Ok(match self {
            UserDefinedType::Array(t) => {
                let mut size = t.element_type.size(tags)?;
                for dim in &t.dimensions {
                    size *= dim.size.map(|u| u.get()).unwrap_or_default();
                }
                size
            }
            UserDefinedType::Structure(t) => t.byte_size,
            UserDefinedType::Enumeration(t) => t.byte_size,
            UserDefinedType::Union(t) => t.byte_size,
            UserDefinedType::Subroutine(_) => 0,
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
    pub fn size(&self, tags: &TagMap) -> Result<u32> {
        if self.modifiers.iter().any(|m| matches!(m, Modifier::PointerTo | Modifier::ReferenceTo)) {
            return Ok(4);
        }
        match self.kind {
            TypeKind::Fundamental(ft) => ft.size(),
            TypeKind::UserDefined(key) => {
                let tag = tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate user defined type {}", key))?;
                let ud_type = ud_type(tags, tag)?;
                ud_type.size(tags)
            }
        }
    }
}

pub fn apply_modifiers(mut str: TypeString, modifiers: &[Modifier]) -> Result<TypeString> {
    let mut has_pointer = false;
    for &modifier in modifiers.iter().rev() {
        match modifier {
            Modifier::PointerTo => {
                if !has_pointer && !str.suffix.is_empty() {
                    str.prefix.push_str(" (*");
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

#[derive(Debug)]
pub struct TypeString {
    pub prefix: String,
    pub suffix: String,
}

impl Display for TypeString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.prefix, self.suffix)
    }
}

pub fn type_string(tags: &TagMap, typedefs: &TypedefMap, t: &Type) -> Result<TypeString> {
    let str = match t.kind {
        TypeKind::Fundamental(ft) => {
            TypeString { prefix: fund_type_string(ft)?.to_string(), suffix: String::new() }
        }
        TypeKind::UserDefined(key) => {
            if let Some(&td_key) = typedefs.get(&key).and_then(|v| v.first()) {
                let tag =
                    tags.get(&td_key).ok_or_else(|| anyhow!("Failed to locate typedef {}", key))?;
                let td_name = tag
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("typedef without name"))?;
                TypeString { prefix: td_name.clone(), suffix: String::new() }
            } else {
                let tag = tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate user defined type {}", key))?;
                ud_type_string(tags, typedefs, &ud_type(tags, tag)?)?
            }
        }
    };
    apply_modifiers(str, &t.modifiers)
}

pub fn ud_type_string(
    tags: &TagMap,
    typedefs: &TypedefMap,
    t: &UserDefinedType,
) -> Result<TypeString> {
    Ok(match t {
        UserDefinedType::Array(t) => {
            let mut out = type_string(tags, typedefs, t.element_type.as_ref())?;
            for dim in &t.dimensions {
                ensure!(
                    matches!(
                        dim.index_type.kind,
                        TypeKind::Fundamental(FundType::Long | FundType::Integer)
                    ),
                    "Unsupported array index type '{}'",
                    type_string(tags, typedefs, &dim.index_type)?
                );
                match dim.size {
                    None => out.suffix.insert_str(0, "[]"),
                    Some(size) => out.suffix = format!("[{}]{}", size, out.suffix),
                };
            }
            out
        }
        UserDefinedType::Structure(t) => {
            let struct_str = if let Some(name) = t.name.as_ref() {
                format!("struct {}", name)
            } else {
                struct_def_string(tags, typedefs, t)?
            };
            TypeString { prefix: struct_str, suffix: String::new() }
        }
        UserDefinedType::Enumeration(t) => {
            let struct_str = if let Some(name) = t.name.as_ref() {
                format!("enum {}", name)
            } else {
                enum_def_string(t)?
            };
            TypeString { prefix: struct_str, suffix: String::new() }
        }
        UserDefinedType::Union(t) => {
            let struct_str = if let Some(name) = t.name.as_ref() {
                format!("union {}", name)
            } else {
                union_def_string(tags, typedefs, t)?
            };
            TypeString { prefix: struct_str, suffix: String::new() }
        }
        UserDefinedType::Subroutine(t) => {
            let mut out = type_string(tags, typedefs, &t.return_type)?;
            let mut parameters = String::new();
            if t.parameters.is_empty() && t.prototyped {
                parameters = "void".to_string()
            } else {
                for (idx, parameter) in t.parameters.iter().enumerate() {
                    if idx > 0 {
                        write!(parameters, ", ")?;
                    }
                    let ts = type_string(tags, typedefs, &parameter.kind)?;
                    if let Some(name) = &parameter.name {
                        write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
                    } else {
                        write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
                    }
                }
            }
            out.suffix = format!("({}){}", parameters, out.suffix);
            out
        }
    })
}

pub fn ud_type_def(tags: &TagMap, typedefs: &TypedefMap, t: &UserDefinedType) -> Result<String> {
    match t {
        UserDefinedType::Array(_) | UserDefinedType::Subroutine(_) => {
            Err(anyhow!("Can't define non-definition type"))
        }
        UserDefinedType::Structure(t) => Ok(struct_def_string(tags, typedefs, t)?),
        UserDefinedType::Enumeration(t) => Ok(enum_def_string(t)?),
        UserDefinedType::Union(t) => Ok(union_def_string(tags, typedefs, t)?),
    }
}

pub fn struct_def_string(
    tags: &TagMap,
    typedefs: &TypedefMap,
    t: &StructureType,
) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => format!("struct {} {{\n", name),
        None => "struct {\n".to_string(),
    };
    writeln!(out, "\t// total size: {:#X}", t.byte_size)?;
    for member in &t.members {
        let ts = type_string(tags, typedefs, &member.kind)?;
        write!(out, "\t{} {}{}", ts.prefix, member.name, ts.suffix)?;
        if let Some(bit) = &member.bit {
            write!(out, " : {}", bit.bit_size)?;
        }
        writeln!(out, "; // offset {:#X}, size {:#X}", member.offset, member.kind.size(tags)?)?;
    }
    write!(out, "}}")?;
    Ok(out)
}

pub fn enum_def_string(t: &EnumerationType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => format!("enum {} {{\n", name),
        None => "enum {\n".to_string(),
    };
    for member in t.members.iter().rev() {
        writeln!(out, "\t{} = {},", member.name, member.value)?;
    }
    write!(out, "}}")?;
    Ok(out)
}

pub fn union_def_string(tags: &TagMap, typedefs: &TypedefMap, t: &UnionType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => format!("union {} {{\n", name),
        None => "union {\n".to_string(),
    };
    for member in t.members.iter().rev() {
        let ts = type_string(tags, typedefs, &member.kind)?;
        writeln!(out, "\t{} {}{};", ts.prefix, member.name, ts.suffix)?;
    }
    write!(out, "}}")?;
    Ok(out)
}

pub fn fund_type_string(ft: FundType) -> Result<&'static str> {
    Ok(match ft {
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
        | FundType::Label => bail!("Unhandled fundamental type {ft:?}"),
        FundType::LongLong => "long long",
        FundType::SignedLongLong => "signed long long",
        FundType::UnsignedLongLong => "unsigned long long",
    })
}

pub fn process_offset(block: &[u8]) -> Result<u32> {
    if block.len() == 6 && block[0] == LocationOp::Const as u8 && block[5] == LocationOp::Add as u8
    {
        Ok(u32::from_be_bytes(block[1..5].try_into()?))
    } else {
        Err(anyhow!("Unhandled location data, expected offset"))
    }
}

pub fn process_address(block: &[u8]) -> Result<u32> {
    if block.len() == 5 && block[0] == LocationOp::Address as u8 {
        Ok(u32::from_be_bytes(block[1..].try_into()?))
    } else {
        Err(anyhow!("Unhandled location data, expected address"))
    }
}

pub fn process_variable_location(block: &[u8]) -> Result<String> {
    // TODO: float regs
    if block.len() == 5 && block[0] == LocationOp::Register as u8 {
        Ok(format!("r{}", u32::from_be_bytes(block[1..].try_into()?)))
    } else if block.len() == 11
        && block[0] == LocationOp::BaseRegister as u8
        && block[5] == LocationOp::Const as u8
        && block[10] == LocationOp::Add as u8
    {
        Ok(format!(
            "r{}+{:#X}",
            u32::from_be_bytes(block[1..5].try_into()?),
            u32::from_be_bytes(block[6..10].try_into()?)
        ))
    } else {
        Err(anyhow!("Unhandled location data {:?}, expected variable loc", block))
    }
}

pub fn ud_type(tags: &TagMap, tag: &Tag) -> Result<UserDefinedType> {
    match tag.kind {
        TagKind::ArrayType => {
            let mut data = tag
                .block_attribute(AttributeKind::SubscrData)
                .ok_or_else(|| anyhow!("ArrayType without SubscrData"))?;

            let mut element_type = None;
            let mut dimensions = Vec::new();
            while !data.is_empty() {
                let format = SubscriptFormat::try_from(
                    data.first().cloned().ok_or_else(|| anyhow!("Empty SubscrData"))?,
                )
                .context("Unknown array subscript format")?;
                data = &data[1..];
                match format {
                    SubscriptFormat::FundTypeConstConst => {
                        let index_type =
                            FundType::try_from(u16::from_be_bytes(data[..2].try_into()?))
                                .context("Invalid fundamental type ID")?;
                        let low_bound = u32::from_be_bytes(data[2..6].try_into()?);
                        ensure!(low_bound == 0, "Invalid array low bound {low_bound}, expected 0");
                        let high_bound = u32::from_be_bytes(data[6..10].try_into()?);
                        data = &data[10..];
                        dimensions.push(ArrayDimension {
                            index_type: Type {
                                kind: TypeKind::Fundamental(index_type),
                                modifiers: vec![],
                            },
                            // u32::MAX will wrap to 0, meaning unbounded
                            size: NonZeroU32::new(high_bound.wrapping_add(1)),
                        });
                    }
                    SubscriptFormat::ElementType => {
                        let mut cursor = Cursor::new(data);
                        let type_attr = read_attribute(&mut cursor)?;
                        element_type = Some(process_type(&type_attr)?);
                        data = &data[cursor.position() as usize..];
                    }
                    _ => bail!("Unhandled subscript format type {:?}", format),
                }
            }
            if let Some(element_type) = element_type {
                Ok(UserDefinedType::Array(ArrayType {
                    element_type: Box::from(element_type),
                    dimensions,
                }))
            } else {
                Err(anyhow!("Array type without element type"))
            }
        }
        TagKind::StructureType => {
            let byte_size = tag.data4_attribute(AttributeKind::ByteSize).unwrap_or_default();
            //.ok_or_else(|| {
            //                 anyhow!("StructureType without ByteSize: {:?}", tag)
            //             })?
            let name = tag.string_attribute(AttributeKind::Name).cloned();
            let mut members = Vec::new();
            for child in tag.children(tags) {
                ensure!(
                    child.kind == TagKind::Member,
                    "Unhandled StructureType child {:?}",
                    child.kind
                );

                let member_name = child
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("Structure member without name: {:?}", child))?;
                let member_type = process_type(
                    child
                        .type_attribute()
                        .ok_or_else(|| anyhow!("Structure member without type: {:?}", child))?,
                )?;
                if let Some(member_of) = child.reference_attribute(AttributeKind::Member) {
                    ensure!(
                        member_of == tag.key,
                        "Structure member mismatch: {} != {}",
                        member_of,
                        tag.key
                    );
                }

                let location = child
                    .block_attribute(AttributeKind::Location)
                    .ok_or_else(|| anyhow!("Structure member without location: {:?}", child))?;
                let offset = process_offset(location)?;

                let bit = match (
                    child.data4_attribute(AttributeKind::ByteSize),
                    child.data4_attribute(AttributeKind::BitSize),
                    child.data2_attribute(AttributeKind::BitOffset),
                ) {
                    (Some(byte_size), Some(bit_size), Some(bit_offset)) => {
                        Some(BitData { byte_size, bit_size, bit_offset })
                    }
                    (None, None, None) => None,
                    _ => bail!("Mismatched bit attributes in structure member: {child:?}"),
                };
                members.push(StructureMember {
                    name: member_name.clone(),
                    kind: member_type,
                    offset,
                    bit,
                });
            }
            Ok(UserDefinedType::Structure(StructureType { name, byte_size, members }))
        }
        TagKind::EnumerationType => {
            let byte_size = tag
                .data4_attribute(AttributeKind::ByteSize)
                .ok_or_else(|| anyhow!("EnumerationType without ByteSize"))?;
            let data = tag
                .block_attribute(AttributeKind::ElementList)
                .ok_or_else(|| anyhow!("EnumerationType without ElementList"))?;
            let name = tag.string_attribute(AttributeKind::Name).cloned();
            let mut members = Vec::new();
            let mut cursor = Cursor::new(data);
            while cursor.position() < data.len() as u64 {
                let value = cursor.read_u32::<BigEndian>()?;
                let name = read_string(&mut cursor)?;
                members.push(EnumerationMember { name, value });
            }
            Ok(UserDefinedType::Enumeration(EnumerationType { name, byte_size, members }))
        }
        TagKind::UnionType => {
            let byte_size = tag
                .data4_attribute(AttributeKind::ByteSize)
                .ok_or_else(|| anyhow!("UnionType without ByteSize"))?;
            let name = tag.string_attribute(AttributeKind::Name).cloned();
            let mut members = Vec::new();
            for child in tag.children(tags) {
                ensure!(
                    child.kind == TagKind::Member,
                    "Unhandled UnionType child {:?}",
                    child.kind
                );

                let member_name = child
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("Structure member without name: {:?}", child))?;
                let member_type = process_type(
                    child
                        .type_attribute()
                        .ok_or_else(|| anyhow!("Structure member without type: {:?}", child))?,
                )?;
                if let Some(member_of) = child.reference_attribute(AttributeKind::Member) {
                    ensure!(
                        member_of == tag.key,
                        "Structure member mismatch: {member_of} != {}",
                        tag.key
                    );
                }

                let location = child
                    .block_attribute(AttributeKind::Location)
                    .ok_or_else(|| anyhow!("Structure member without location: {:?}", child))?;
                ensure!(process_offset(location)? == 0, "Union member at non-zero offset");

                members.push(UnionMember { name: member_name.clone(), kind: member_type });
            }
            Ok(UserDefinedType::Union(UnionType { name, byte_size, members }))
        }
        TagKind::SubroutineType | TagKind::GlobalSubroutine | TagKind::Subroutine => {
            let return_type = match tag.type_attribute() {
                Some(attr) => process_type(attr)?,
                None => Type { kind: TypeKind::Fundamental(FundType::Void), modifiers: vec![] },
            };
            let prototyped = tag.string_attribute(AttributeKind::Prototyped).is_some();
            let mut parameters = Vec::new();
            let mut var_args = false;
            for child in tag.children(tags) {
                if tag.kind != TagKind::SubroutineType
                    && child.kind != TagKind::FormalParameter
                    && child.kind != TagKind::UnspecifiedParameters
                {
                    break;
                }
                ensure!(!var_args, "{:?} after UnspecifiedParameters", child.kind);
                match child.kind {
                    TagKind::FormalParameter => {
                        let parameter_name = child.string_attribute(AttributeKind::Name).cloned();
                        let parameter_type =
                            process_type(child.type_attribute().ok_or_else(|| {
                                anyhow!("FormalParameter without type: {:?}", child)
                            })?)?;
                        parameters.push(SubroutineParameter {
                            name: parameter_name,
                            kind: parameter_type,
                        });
                    }
                    TagKind::UnspecifiedParameters => {
                        var_args = true;
                    }
                    _ => bail!("Unhandled SubroutineType child {:?}", child.kind),
                }
            }
            Ok(UserDefinedType::Subroutine(SubroutineType {
                return_type,
                parameters,
                var_args,
                prototyped,
            }))
        }
        kind => Err(anyhow!("Unhandled user defined type {kind:?}")),
    }
}

pub fn process_modifiers(block: &[u8]) -> Result<Vec<Modifier>> {
    let mut out = Vec::with_capacity(block.len());
    for &b in block {
        out.push(Modifier::try_from(b)?);
    }
    Ok(out)
}

pub fn process_type(attr: &Attribute) -> Result<Type> {
    match attr.kind {
        AttributeKind::FundType => {
            if let AttributeValue::Data2(type_id) = attr.value {
                let fund_type = FundType::try_from(type_id)
                    .with_context(|| format!("Invalid fundamental type ID '{}'", type_id))?;
                Ok(Type { kind: TypeKind::Fundamental(fund_type), modifiers: vec![] })
            } else {
                Err(anyhow!("Invalid value type for FundType"))
            }
        }
        AttributeKind::ModFundType => {
            if let AttributeValue::Block(ops) = &attr.value {
                let type_id = u16::from_be_bytes(ops[ops.len() - 2..].try_into()?);
                let fund_type = FundType::try_from(type_id)
                    .with_context(|| format!("Invalid fundamental type ID '{}'", type_id))?;
                let modifiers = process_modifiers(&ops[..ops.len() - 2])?;
                Ok(Type { kind: TypeKind::Fundamental(fund_type), modifiers })
            } else {
                Err(anyhow!("Invalid value type for ModFundType"))
            }
        }
        AttributeKind::UserDefType => {
            if let AttributeValue::Reference(key) = attr.value {
                Ok(Type { kind: TypeKind::UserDefined(key), modifiers: vec![] })
            } else {
                Err(anyhow!("Invalid value type for UserDefType"))
            }
        }
        AttributeKind::ModUDType => {
            if let AttributeValue::Block(ops) = &attr.value {
                let ud_ref = u32::from_be_bytes(ops[ops.len() - 4..].try_into()?);
                let modifiers = process_modifiers(&ops[..ops.len() - 4])?;
                Ok(Type { kind: TypeKind::UserDefined(ud_ref), modifiers })
            } else {
                Err(anyhow!("Invalid value type for ModUDType"))
            }
        }
        _ => Err(anyhow!("Invalid type attribute kind {:?}", attr.kind)),
    }
}
