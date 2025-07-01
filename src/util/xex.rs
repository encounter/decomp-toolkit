use std::{
    collections::{hash_map, HashMap},
    fs,
    io::Cursor,
    num::NonZeroU64,
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use cwdemangle::demangle;
use flagset::Flags;
use indexmap::IndexMap;
use itertools::Itertools;
use objdiff_core::obj::split_meta::{SplitMeta, SHT_SPLITMETA, SPLITMETA_SECTION};
use object::{
    read::pe::PeFile64, Architecture, BinaryFormat, Endianness, File, Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget, SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection
};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    analysis::cfa::SectionAddress, array_ref, obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    }, util::{
        comment::{CommentSym, MWComment},
        reader::{Endian, FromReader, ToWriter},
    }
};

use num_enum::{ TryFromPrimitive, IntoPrimitive };

#[derive(thiserror::Error, Debug)]
pub enum XexError {
    #[error("XEX2 header not found!")]
    HeaderNotFound,
    #[error("No data found in optional header!")]
    HeaderDataNotFound
}

// ----------------------------------------------------------------------
// XEXHEADER
// ----------------------------------------------------------------------

// header documentation: https://free60.org/System-Software/Formats/XEX/
pub struct XexHeader {
    // magic u32 here - must be "XEX2"
    pub module_flags: u32,
    pub pe_offset: u32,
    // reserved u32 here, but it goes unused so who cares
    pub security_info_offset: u32
}

impl XexHeader {
    fn parse(data: &Vec<u8>) -> Result<Self, XexError> {
        let magic = read_word(&data, 0);
        if magic != 0x58455832 {
            return Err(XexError::HeaderNotFound);
        }
        let module_flags = read_word(&data, 4);
        let pe_offset = read_word(&data, 8);
        // reserved is at data index 12, but it's unused so who cares
        let security_info_offset = read_word(&data, 16);
        return Ok(Self { module_flags, pe_offset, security_info_offset });
    }
}

// ----------------------------------------------------------------------
// XEXOPTIONALHEADERDATA
// ----------------------------------------------------------------------

pub struct XexOptionalHeaderData {
    // Vec<XexOptionalHeader>?
    pub original_name: String,
    pub entry_point: u32,
    pub image_base: u32,
    // BaseFileFormat
    // PatchDescriptor
    // ImportLibraries
}

impl XexOptionalHeaderData {
    fn parse(data: &Vec<u8>) -> Result<Self, XexError> {
        // read in the optional headers
        let num_optional_headers = read_word(&data, 20);
        let mut opt_headers: Vec<XexOptionalHeader> = vec![];
        for n in 0..num_optional_headers {
            opt_headers.push(XexOptionalHeader::new(data, (24 + n * 8) as usize));
        }

        let mut original_name = String::new();
        let mut entry_point = 0;
        let mut image_base = 0;

        // and now, process them
        for header in opt_headers {
            if header.data.is_empty() {
                return Err(XexError::HeaderDataNotFound);
            }
            match header.id {
                XexOptionalHeaderID::ResourceInfo => {
                    log::info!("Resource info: {:?}", String::from_utf8(header.data.clone()));
                }
                XexOptionalHeaderID::BaseFileFormat => {
                    log::info!("handle base file format here");
                }
                XexOptionalHeaderID::DeltaPatchDescriptor => {
                    log::info!("TODO: handle patch descriptor");
                }
                XexOptionalHeaderID::BoundingPath => {
                    log::info!("bounding path here");
                }
                XexOptionalHeaderID::EntryPoint => {
                    entry_point = header.value;
                    log::info!("Entry point addr: 0x{:X}", entry_point);
                }
                XexOptionalHeaderID::ImageBaseAddress => {
                    image_base = header.value;
                    log::info!("Image base addr: 0x{:X}", image_base);
                }
                XexOptionalHeaderID::ImportLibraries => {
                    log::info!("import libs here");
                    // log::info!("{:?}", header.data);
                }
                XexOptionalHeaderID::OriginalPEName => {
                    original_name = String::from_utf8(header.data.clone()).ok().unwrap();
                    log::info!("Original PE Name: {}", original_name);
                }
                _ => {
                    log::info!("unhandled header ID {:?}", header.id);
                }
            }
        }
        return Ok(Self { original_name, entry_point, image_base });
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum XexOptionalHeaderID {
    ResourceInfo = 0x2FF,
    BaseFileFormat = 0x3FF,
    BaseReference = 0x405,
    DeltaPatchDescriptor = 0x5FF,
    BoundingPath = 0x80FF,
    DeviceID = 0x8105,
    OriginalBaseAddress = 0x10001,
    EntryPoint = 0x10100,
    ImageBaseAddress = 0x10201,
    ImportLibraries = 0x103FF,
    ChecksumTimestamp = 0x18002,
    EnabledForCallcap = 0x18102,
    EnabledForFastcap = 0x18200,
    OriginalPEName = 0x183FF,
    StaticLibraries = 0x200FF,
    TLSInfo = 0x20104,
    DefaultStackSize = 0x20200,
    DefaultFilesystemCacheSize = 0x20301,
    DefaultHeapSize = 0x20401,
    PageHeapSizeAndFlags = 0x28002,
    SystemFlags = 0x30000,
    // extra flag found! 0x30100
    ExecutionID = 0x40006,
    ServiceIDList = 0x401FF,
    TitleWorkspaceSize = 0x40201,
    GameRatings = 0x40310,
    LANKey = 0x40404,
    Xbox360Logo = 0x405FF,
    MultidiscMediaIDs = 0x406FF,
    AlternateTitleIDs = 0x407FF,
    AdditionalTitleMemory = 0x40801,
    ExportsByName = 0xE10402
}

pub struct XexOptionalHeader {
    pub id: XexOptionalHeaderID,
    pub value: u32,
    pub data: Vec<u8>
}

impl XexOptionalHeader {
    pub fn new(data: &Vec<u8>, index: usize) -> Self {
        let mut hdr = Self { id: XexOptionalHeaderID::try_from(read_word(data, index)).unwrap(), value: read_word(data, index + 4), data: Vec::new() };

        let id_as_u32: u32 = hdr.id.into();
        let mask = id_as_u32 & 0xFF;
        if mask == 0xFF {
            // seek the binstream to hdr.value, read the word (that's your len)
            let len = read_word(data, hdr.value as usize);
            let start: usize = (hdr.value + 4) as usize;
            let end: usize = (hdr.value + len) as usize;
            hdr.data = data[start..end].to_vec();
        }
        else if mask < 2 {
            // data = value as a Vec<u8>
            // println!("for ID 0x{:X}, value = 0x{:X}", id_as_u32, hdr.value);
            hdr.data = data[index..index + 4].to_vec();
        }
        else {
            let len = mask * 4;
            let start: usize = (hdr.value + 4) as usize;
            let end: usize = (hdr.value + len) as usize;
            hdr.data = data[start..end].to_vec();
        }
        return hdr;
    }
}

const MODULE_FLAGS: [&str; 8] = [ "Title Module", "Exports To Title", "System Debugger", "DLL Module", "Module Patch", "Patch Full", "Patch Delta", "User Mode" ];

pub struct XexInfo {
    pub header: XexHeader,
    pub opt_header_data: XexOptionalHeaderData
}

impl XexInfo {
    pub fn from_file(path: &Utf8NativePath) -> Result<Self, XexError> {
        let std_path = path.to_path_buf();
        let data = fs::read(std_path).expect("Failed to read file");

        let xex_header = match XexHeader::parse(&data) {
            Ok(header) => header,
            Err(e) => return Err(e)
        };

        let xex_optional_header_data = match XexOptionalHeaderData::parse(&data){
            Ok(data) => data,
            Err(e) => return Err(e)
        };

        // -- set up loader info
        // -- try to deduce session key (could be retail, could be devkit, we dunno)
        // -- xexsection stuff??? (might not be needed?)

        return Ok(Self { header: xex_header, opt_header_data: xex_optional_header_data });
    }
}

// struct XexInfo? after the exe is pulled out from the xex, transfer anything necessary to ObjInfo
    // const uint XEX2_MAGIC = 0x58455832; // 'XEX2'
    // public uint magic;
    // public uint moduleFlags;
    // public uint peDataOffset;
    // public uint reserved;
    // public uint securityInfoOffset;
    // public uint optionalHeaderCount;
    // public List<XexOptionalHeader> optionalHeaders;
    // public BaseFileFormat baseFileFormat;
    // public List<String> stringTable;
    // public List<ImportLibrary> importLibs;
    // public XexLoaderInfo loaderInfo = new();
    // public byte[] sessionKey;
    // public List<XexSection> sections = new();
    // public byte[] peImage;

pub fn read_word(data: &Vec<u8>, index: usize) -> u32 {
    return u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
}

pub fn extract_exe(path: &Utf8NativePath) -> Result<()> {
    println!("xex: {path}");
    let xex = XexInfo::from_file(path);
    // after this line, the XexInfo should have all of its relevant metadata parsed
    // so, try to read the PE image

    // let pe_file = PeFile64::parse(&*data);
    Ok(())
}

pub fn process_xex(path: &Utf8NativePath) -> Result<ObjInfo> {
    // look at cmd\dol\split
    println!("xex: {path}");
    let std_path = path.to_path_buf();
    let data = fs::read(std_path).expect("Failed to read file");
    let obj_file = object::File::parse(&*data).expect("Failed to parse object file");
    let architecture = ObjArchitecture::PowerPc;
    let kind = ObjKind::Executable;

    // TODO: rename this to the underlying executable name found in the xex
    let mut obj_name = "jeff";

    let mut sections: Vec<ObjSection> = vec![];
    let mut section_indexes: Vec<Option<usize>> = vec![None /* ELF null section */];
    for section in obj_file.sections() {
        if section.size() == 0 {
            section_indexes.push(None);
            continue;
        }
        let section_name = section.name()?;
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            // SectionKind::Other if section_name == ".comment" => ObjSectionKind::Comment,
            _ => {
                section_indexes.push(None);
                continue;
            }
        };
        section_indexes.push(Some(sections.len())); // the .XBLD and .reloc section indices aren't pushed. is that intentional?
        // should we do anything with section.flags()? xex uses COFF
        sections.push(ObjSection {
            name: section_name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section.uncompressed_data()?.to_vec(),
            align: section.align(),
            // the index of the section in the exe - starts at 1 instead of 0 for some reason, so offset it by -1
            elf_index: (section.index().0 - 1) as ObjSectionIndex,
            // everything below this line doesn't really matter for the purposes of an xex
            relocations: Default::default(),
            virtual_address: None, // Loaded from section symbol
            file_offset: section.file_range().map(|(v, _)| v).unwrap_or_default(),
            section_known: true,
            splits: Default::default(),
        });
    }

    // Create object
    let mut obj = ObjInfo::new(kind, architecture, obj_name.to_string(), vec![], sections);
    obj.entry = NonZeroU64::new(obj_file.entry()).map(|n| n.get());

    // add known function boundaries from pdata
    // pdata info: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
    let pdata_section = obj.sections.by_name(".pdata")?.map(|(_, s)| s).ok_or_else(|| anyhow::anyhow!(".pdata section not found"))?;
    let text_index = obj.sections.by_name(".text")?.map(|(_, s)| s).ok_or_else(|| anyhow::anyhow!(".text section not found"))?.elf_index;
            
    for (i, chunk) in pdata_section.data.chunks_exact(8).enumerate() {
        // the addr where this function begins
        let start_addr = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        // if we encounter 0's, that's the end of usable pdata entries
        if start_addr == 0 {
            log::info!("Found {} known funcs from pdata!", i);
            // log::info!("Encountered 0 at addr 0x{:08X}", pdata_section.address + (8 * i) as u64);
            break;
        }
        // some metadata for this function, including function size
        let word = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
        // let num_prologue_insts = word & 0xFF; // The number of instructions in the function's prolog.
        let num_insts_in_func = (word >> 8) & 0x3FFFFF; // The number of instructions in the function.
        // let flag_32bit = (word & 0x4000) != 0; // If set, the function consists of 32-bit instructions. If clear, the function consists of 16-bit instructions.
        // let exception_flag = (word & 0x8000) != 0; // If set, an exception handler exists for the function. Otherwise, no exception handler exists.
        
        // log::info!("Found func {} from 0x{:08X}-0x{:08X}", i, start_addr, start_addr + (num_insts_in_func * 4));
        let start = SectionAddress::new(text_index, start_addr);
        obj.known_functions.insert(start, Some(num_insts_in_func * 4));
    }

    // if we have an .xidata section...
    //      then we have symbols like XamInputGetCapabilities to label within .xidata
    //      and imps like __imp_XamInputGetCapabilities are in .idata
    // else...
    //      symbols like XamInputGetCapabilities are appended to .text
    //      and imps like __imp_XamInputGetCapabilities are in .rdata

    // xidata notes:
    // stripped (0x82173e40)
    // XamInputGetCapabilities: 01 00 01 90 02 00 01 90 7D 69 03 A6 4E 80 04 20
    // unstripped
    // XamInputGetCapabilities: 3D 60 82 71 81 6B 03 C4 7D 69 03 A6 4E 80 04 20

    // stripped (0x827103c4)
    // __imp_XamInputGetCapabilities: 00 00 01 90
    // unstripped
    // __imp_XamInputGetCapabilities: 90 01 00 80

    // stripped search templates:
    // API: 01 00 xx xx 02 00 xx xx 7D 69 03 A6 4E 80 04 20
    // imp: 00 00 xx xx

    // some xidata notes (idk where else to put them lol)
    // part 1:
    // seems to be many many lis/addi/mtctr/bctrs in sequence
    // e.g. lis r11, 0x82XX / addi r11, r11, 0xXXXX / mtctr r11 / bctr
    // indirect function calls? stubs?
    // matches up just fine

    // part 2: a bunch of 0's

    // part 3:
    // many lis/lwz/mtctr/bctrs in sequence
    // e.g. lis r11, 0xXXXX / lwz r11, 0xXXXX(r11) / mtctr r11/ bctr / zero-padding
    // this does not quite match up with the ground truth, but I suspect the difference comes from relocs

    // .XBMOVIE: matches up with ground truth...but it's mostly a sea of 0's
    // .idata: partially zero'ed out and offsetted from ground truth in debug, completely gone from release
    // .XBLD: zero'ed out in debug, completely gone from release
    // .reloc: zero'ed out regardless

    Ok(obj)
}