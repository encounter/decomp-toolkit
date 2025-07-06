use std::{ borrow::Cow, fs, num::NonZeroU64 };
use std::cmp::min;
use anyhow::{anyhow, bail, ensure, Result};
use object::{
    endian, read::pe::PeFile32, Architecture, BinaryFormat, Endianness, File, Import,
    Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget,
    SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection
};
use typed_path::Utf8NativePathBuf;

use crate::{
    analysis::cfa::SectionAddress, obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    },
    util::{ crypto::decrypt_aes128_cbc_no_padding, xex_imports::replace_ordinal }
};

use num_enum::{ TryFromPrimitive, IntoPrimitive };
use crate::obj::SymbolIndex;

// quick and ez ways to read data from a block of bytes
pub fn read_halfword(data: &Vec<u8>, index: usize) -> u16 {
    return u16::from_be_bytes([data[index], data[index + 1]]);
}

pub fn read_word(data: &Vec<u8>, index: usize) -> u32 {
    return u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
}

// ----------------------------------------------------------------------
// BASEFILEFORMAT
// ----------------------------------------------------------------------

pub struct BasicCompression {
    pub data_size: u32,
    pub zero_size: u32   
}

pub struct NormalCompression {
    pub window_size: u32,
    pub block_size: u32,
    pub block_hash: [u8; 20]
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum XexEncryption {
    No = 0,
    Yes = 1
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum XexCompression {
    None = 0,
    Raw = 1,
    Compressed = 2,
    DeltaCompressed = 3
}

pub struct BaseFileFormat {
    pub encryption: XexEncryption,
    pub compression: XexCompression,
    pub basics: Vec<BasicCompression>,
    pub normal: Option<NormalCompression>
}

impl BaseFileFormat {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let encryption = XexEncryption::try_from(read_halfword(&data, 0))?;
        let compression = XexCompression::try_from(read_halfword(&data, 2))?;
        let mut basics: Vec<BasicCompression> = vec![];
        let mut normal = None;
        match compression {
            XexCompression::None => {}
            XexCompression::Raw => {
                let count = (data.len() - 4) / 8;
                for i in 0..count {
                    basics.push(BasicCompression { data_size: read_word(&data, 4 + i * 8), zero_size: read_word(&data, 8 + i * 8) });
                }
            }
            XexCompression::Compressed | XexCompression::DeltaCompressed => {
                normal = Some(NormalCompression { window_size: read_word(&data, 4), block_size: read_word(&data, 8), block_hash: data[12..32].try_into()? });
            }
        }
        return Ok(Self { encryption, compression, basics, normal } );
    }
}

// ----------------------------------------------------------------------
// IMPORTLIBRARIES
// ----------------------------------------------------------------------

pub struct ImportLibraries {
    pub libraries: Vec<ImportLibrary>,
}

pub struct ImportFunction {
    pub address: u32,
    pub ordinal: u32,
    pub thunk: u32
}

pub struct ImportLibrary {
    pub name: String,
    pub records: Vec<u32>,
    pub functions: Vec<ImportFunction>
}

impl ImportLibraries {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let string_size = read_word(&data, 0);
        let lib_count = read_word(&data, 4);

        // populate the string table
        let mut string_table: Vec<String> = vec![];
        let mut pos: usize = 8;
        let mut cur_str = String::new();
        let cap: usize = (string_size + 8) as usize;
        while pos < cap {
            if data[pos] != 0 {
                cur_str += &(data[pos] as char).to_string();
            }
            else {
                while data[pos + 1] == 0 && pos < cap - 1 {
                    pos += 1;
                }
                string_table.push(cur_str.clone());
                cur_str.clear();
            }
            pos += 1;
        }

        // actually parse the import libraries
        pos = cap;
        let mut libraries: Vec<ImportLibrary> = vec![];
        for _ in 0..lib_count {
            pos += 0x24;
            let name_idx = read_halfword(&data, pos) as usize;
            let count = read_halfword(&data, pos + 2) as usize;
            pos += 4;
            let lib_name = &string_table[name_idx];
            let mut records: Vec<u32> = vec![];
            for i in 0..count {
                records.push(read_word(data, pos + (i * 4)));
            }
            pos += count * 4;
            libraries.push(ImportLibrary { name: lib_name.clone(), records: records, functions: Vec::new() });
        }
        return Ok(Self { libraries } );

    }
}

// ----------------------------------------------------------------------
// RESOURCEINFO
// ----------------------------------------------------------------------

pub struct ResourceInfo {
    pub title_id: String,
    pub rsrc_start: u32,
    pub rsrc_end: u32
}

impl ResourceInfo {
    pub fn parse(data: &Vec<u8>) -> Result<Self> {
        ensure!(data.len() == 16, "Resource info has unexpected length! (expected 16)");
        let title_id = String::from_utf8(data[0..8].to_vec())?;
        let rsrc_start = read_word(&data, 8);
        let rsrc_end = rsrc_start + read_word(&data, 12);
        return Ok(Self { title_id, rsrc_start, rsrc_end });
    }
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
    fn parse(data: &Vec<u8>) -> Result<Self> {
        let magic = read_word(&data, 0);
        ensure!(magic == 0x58455832, "XEX2 magic header not found!");
        let module_flags = read_word(&data, 4);
        let pe_offset = read_word(&data, 8);
        // reserved is at data index 12, but it's unused so who cares
        let security_info_offset = read_word(&data, 16);
        return Ok(Self { module_flags, pe_offset, security_info_offset });
    }
}

// ----------------------------------------------------------------------
// STATICLIBRARY
// ----------------------------------------------------------------------

pub struct StaticLibrary {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub qfe: u8,
    pub approval_type: u8
}

// ----------------------------------------------------------------------
// XEXOPTIONALHEADERDATA
// ----------------------------------------------------------------------

pub struct XexOptionalHeaderData {
    // Vec<XexOptionalHeader>? should we keep the vector of optional headers we find?
    pub original_name: String,
    pub entry_point: u32,
    pub image_base: u32,
    pub file_timestamp: u32,
    pub resource_info: Option<ResourceInfo>,
    pub base_file_format: Option<BaseFileFormat>,
    // PatchDescriptor
    pub static_libs: Vec<StaticLibrary>,
    pub import_libs: Option<ImportLibraries>,
}

impl XexOptionalHeaderData {
    fn parse(data: &Vec<u8>) -> Result<Self> {
        // read in the optional headers
        let num_optional_headers = read_word(&data, 20);
        let mut opt_headers: Vec<XexOptionalHeader> = vec![];
        for n in 0..num_optional_headers {
            opt_headers.push(XexOptionalHeader::new(data, (24 + n * 8) as usize));
        }

        let mut original_name = String::new();
        let mut entry_point = 0;
        let mut image_base = 0;
        let mut file_timestamp = 0;
        let mut import_libs = None;
        let mut resource_info = None;
        let mut base_file_format = None;
        let mut static_libs: Vec<StaticLibrary> = vec![];

        // and now, process them
        for header in opt_headers {
            ensure!(!header.data.is_empty(), "No data found in optional header!");
            match header.id {
                XexOptionalHeaderID::ResourceInfo => {
                    resource_info = Some(ResourceInfo::parse(&header.data)?);
                }
                XexOptionalHeaderID::BaseFileFormat => {
                    base_file_format = Some(BaseFileFormat::parse(&header.data)?);
                }
                XexOptionalHeaderID::DeltaPatchDescriptor => {
                    log::debug!("TODO: handle patch descriptor");
                }
                XexOptionalHeaderID::BoundingPath => {
                    log::debug!("TODO: handle bounding path");
                }
                XexOptionalHeaderID::EntryPoint => {
                    entry_point = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::ImageBaseAddress => {
                    image_base = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::ImportLibraries => {
                    import_libs = Some(ImportLibraries::parse(&header.data)?);
                }
                XexOptionalHeaderID::OriginalPEName => {
                    original_name = String::from_utf8(header.data.clone())?;
                }
                XexOptionalHeaderID::ChecksumTimestamp => {
                    file_timestamp = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::StaticLibraries => {
                    let num_libs = header.data.len() / 16;
                    for i in 0..num_libs {
                        let start = i * 16;
                        static_libs.push(StaticLibrary {
                            name: String::from_utf8(header.data[start..start + 8].to_vec())?,
                            major: read_halfword(&header.data, start + 8),
                            minor: read_halfword(&header.data, start + 10),
                            build: read_halfword(&header.data, start + 12),
                            qfe: header.data[start + 15],
                            approval_type: header.data[start + 14]
                        });
                    }
                }
                _ => {
                    log::warn!("unhandled header ID {:?}", header.id);
                }
            }
        }
        // at the very minimum, we should have a base file format, as that contains encryption/compression information
        ensure!(base_file_format.is_some(), "Base file format not found!");
        return Ok(Self { original_name, entry_point, image_base, file_timestamp, resource_info, base_file_format, static_libs, import_libs });
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
    Unknown30100 = 0x30100,
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
            hdr.data = data[index + 4..index + 8].to_vec();
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

// ----------------------------------------------------------------------
// XEXLOADERINFO
// ----------------------------------------------------------------------

pub struct XexLoaderInfo {
    pub header_size: u32,
    pub image_size: u32,
    pub rsa_signature: [u8; 256],
    pub unknown: u32,
    pub image_flags: u32,
    pub load_address: u32,
    pub section_digest: [u8; 20],
    pub import_table_count: u32,
    pub import_table_digest: [u8; 20],
    pub media_id: [u8; 16],
    pub file_key: [u8; 16],
    pub export_table: u32,
    pub header_digest: [u8; 20],
    pub game_regions: u32,
    pub media_flags: u32,
}

impl XexLoaderInfo {
    fn parse(data: &Vec<u8>, security_offset: u32) -> Result<Self> {
        let mut pos = security_offset as usize;
        let header_size = read_word(&data, pos);
        let image_size = read_word(&data, pos + 4);
        pos += 8;
        let rsa_signature = data[pos..pos + 256].try_into()?;
        pos += 256;
        let unknown = read_word(&data, pos);
        let image_flags = read_word(&data, pos + 4);
        let load_address = read_word(&data, pos + 8);
        pos += 12;
        let section_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let import_table_count = read_word(&data, pos);
        pos += 4;
        let import_table_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let media_id = data[pos..pos + 16].try_into()?;
        pos += 16;
        let file_key = data[pos..pos + 16].try_into()?;
        pos += 16;
        let export_table = read_word(&data, pos);
        pos += 4;
        let header_digest = data[pos..pos + 20].try_into()?;
        pos += 20;
        let game_regions = read_word(&data, pos);
        let media_flags = read_word(&data, pos + 4);
        return Ok(Self {
            header_size, image_size, rsa_signature, unknown, image_flags, load_address,
            section_digest, import_table_count, import_table_digest, media_id,
            file_key, export_table, header_digest, game_regions, media_flags
        });
    }
}

// ----------------------------------------------------------------------
// XEXSESSIONKEYS
// ----------------------------------------------------------------------
const RETAIL_KEY: [u8; 16] = [ 0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3, 0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91 ];
const DEVKIT_KEY: [u8; 16] = [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];

pub struct XexSessionKeys {
    pub session_key_retail: [u8; 16],
    pub session_key_devkit: [u8; 16],
}

impl XexSessionKeys {
    fn derive_keys(file_key: &[u8; 16]) -> Result<Self> {
        let retail_derived_key: [u8; 16] = decrypt_aes128_cbc_no_padding(&RETAIL_KEY, file_key)?.try_into().unwrap();
        let devkit_derived_key: [u8; 16] = decrypt_aes128_cbc_no_padding(&DEVKIT_KEY, file_key)?.try_into().unwrap();
        // print!("Retail session key: ");
        // for k in retail_derived_key {
        //     print!("{:02X} ", k);
        // }
        // print!("\n");
        // print!("Devkit session key: ");
        // for k in devkit_derived_key {
        //     print!("{:02X} ", k);
        // }
        // print!("\n");
        return Ok( Self { session_key_retail: retail_derived_key, session_key_devkit: devkit_derived_key });
    }
}

// ----------------------------------------------------------------------
// XEXINFO
// ----------------------------------------------------------------------

pub struct XexInfo {
    pub header: XexHeader,
    pub opt_header_data: XexOptionalHeaderData,
    pub loader_info: XexLoaderInfo,
    pub session_key: [u8; 16],
    pub is_dev_kit: bool,
    pub exe_bytes: Vec<u8>
}

impl XexInfo {
    pub fn from_file(path: &Utf8NativePathBuf) -> Result<Self> {
        let std_path = path.to_path_buf();
        let data = fs::read(std_path).expect("Failed to read file");

        let xex_header = XexHeader::parse(&data)?;
        let xex_optional_header_data = XexOptionalHeaderData::parse(&data)?;
        let xex_loader_info = XexLoaderInfo::parse(&data, xex_header.security_info_offset)?;
        let xex_session_keys = XexSessionKeys::derive_keys(&xex_loader_info.file_key)?;
        let confirmed_session_key: [u8; 16];
        let is_dev_kit: bool;
        let exe_bytes: Vec<u8>;

        // this is where we'd parse xexsection related info...but it might not be needed?

        let pe_vec = &data[xex_header.pe_offset as usize..data.len()].to_vec();
        let bff = xex_optional_header_data.base_file_format.as_ref().unwrap();
        match XexInfo::try_get_exe(pe_vec, &xex_session_keys.session_key_retail, bff, xex_loader_info.image_size) {
            Ok(exe) => {
                // println!("This xex was built in retail mode!");
                confirmed_session_key = xex_session_keys.session_key_retail;
                is_dev_kit = false;
                exe_bytes = exe;
            }
            Err(_) => {
                match XexInfo::try_get_exe(pe_vec, &xex_session_keys.session_key_devkit, bff, xex_loader_info.image_size){
                    Ok(exe) => {
                        // println!("This xex was built in devkit mode!");
                        confirmed_session_key = xex_session_keys.session_key_devkit;
                        is_dev_kit = true;
                        exe_bytes = exe;
                    }
                    Err(e) => {
                        return Err(e); // here until case 2 is implemented
                        bail!("Could not deduce exe type!");
                    }
                }
            }
        }

        return Ok(Self {
            header: xex_header,
            opt_header_data:xex_optional_header_data,
            loader_info: xex_loader_info,
            session_key: confirmed_session_key,
            is_dev_kit: is_dev_kit,
            exe_bytes: exe_bytes
        });
    }

    pub fn try_get_exe(exe_data: &Vec<u8>, session_key: &[u8; 16], bff: &BaseFileFormat, img_size: u32) -> Result<Vec<u8>> {
        let compressed: Cow<[u8]>;

        match bff.encryption {
            XexEncryption::No => { compressed = Cow::Borrowed(&exe_data); }
            XexEncryption::Yes => {
                compressed = Cow::Owned(decrypt_aes128_cbc_no_padding(&session_key, &exe_data)?);
            }
        }

        let mut pe_image: Vec<u8> = vec![];
        pe_image.resize(img_size as usize, 0);
        let mut pos_in: usize = 0;
        let mut pos_out: usize = 0;

        match bff.compression {
            XexCompression::Raw => {
                for bc in &bff.basics {
                    for i in 0..(bc.data_size as usize) {
                        if pos_in + i as usize >= compressed.len() { break; }
                        pe_image[i + pos_out] = compressed[pos_in + i];
                    }
                    pos_out += (bc.data_size + bc.zero_size) as usize;
                    pos_in += bc.data_size as usize;
                }
            }
            XexCompression::None | XexCompression::DeltaCompressed => { pe_image = compressed.to_vec(); }
            XexCompression::Compressed => {
                bail!("This xex is compressed using LZX, which is not currently supported.");
                // this is actually pretty hard to implement, it involves use of the NormalCompression we retrieved earlier,
                // plus the use of microsoft's LZX decompression algorithms
                // here are some references if you try to attempt this
                // https://github.com/zeroKilo/XEXLoaderWV/blob/master/XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java#L356
                // https://github.com/emoose/idaxex/blob/master/formats/xex.cpp#L819
            }
        }

        ensure!(pe_image[0] == 'M' as u8 && pe_image[1] == 'Z' as u8, "This is not a valid exe!");

        // adjust the byte offsets, because virtual addresses have been thrown off in the initial exe reconstruction process
        let pe_file = PeFile32::parse(&*pe_image).expect("Failed to parse newly pulled out exe file");
        let mut pe_file_adjusted: Vec<u8> = vec![];
        let mut first_flag = false;

        for sec in pe_file.section_table().iter(){
            if !first_flag {
                for i in 0..sec.pointer_to_raw_data.get(endian::LittleEndian) {
                    pe_file_adjusted.push(pe_image[i as usize]);
                }
                first_flag = true;
            }
            // if this section is NOT bss (no uninitialized data)
            if (sec.characteristics.get(endian::LittleEndian) & 0x80) == 0 {
                assert_eq!(pe_file_adjusted.len() as u32, sec.pointer_to_raw_data.get(endian::LittleEndian), "Unexpected PE size at this point!");
                for j in 0..sec.size_of_raw_data.get(endian::LittleEndian) {
                    let offset = (j + sec.virtual_address.get(endian::LittleEndian)) as usize;
                    if offset >= pe_image.len() {
                        pe_file_adjusted.push(0);
                    }
                    else {
                        pe_file_adjusted.push(pe_image[offset]);
                    }
                }
            }
        }
        return Ok(pe_file_adjusted);
    }
}

pub fn extract_exe(input: &Utf8NativePathBuf) -> Result<Vec<u8>> {
    println!("xex: {input}");
    let xex = XexInfo::from_file(input)?;
    // after this line, the XexInfo should have all of its relevant metadata parsed
    return Ok(xex.exe_bytes);
}

pub fn process_xex(path: &Utf8NativePathBuf) -> Result<ObjInfo> {
    // look at cmd\dol\split
    println!("xex: {path}");
    let xex = XexInfo::from_file(path)?;
    let obj_file = PeFile32::parse(&*xex.exe_bytes).expect("Failed to parse object file");
    let architecture = ObjArchitecture::PowerPc;
    let kind = ObjKind::Executable;
    let obj_name = xex.opt_header_data.original_name;

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
        section_indexes.push(Some(sections.len()));
        // should we do anything with section.flags()? xex uses COFF
        sections.push(ObjSection {
            name: section_name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section.uncompressed_data()?.to_vec(),
            align: section.align(),
            // exe indices start at 1...why? i hate you that's why
            elf_index: section.index().0 as ObjSectionIndex,
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

    // inspect the ImportLibraries
    // https://github.com/zeroKilo/XEXLoaderWV/blob/master/XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java#L211
    let mut xex_libs = xex.opt_header_data.import_libs;
    // if we even have import libraries
    if let Some(imports) = xex_libs.as_mut() {
        // first, retrieve the ImportFunctions
        for lib in imports.libraries.iter_mut() {
            for record in lib.records.iter() {
                // so what needs to happen here:
                // record = a virtual memory address
                // get the value inside it, it should be something like (example: 01 00 01 94)
                // the last 3 bytes (00 01 94) is the ordinal, the first byte (01) is the itype
                // if 0, it's a func, if 1, it's a thunk

                let sec = obj.sections.at_address(*record)?.1;
                let offset_within_sec = record - sec.address as u32;
                let value = read_word(&sec.data, offset_within_sec as usize);
                let ordinal = value & 0xFFFF;
                let itype = value >> 24;
                match itype {
                    0 => {
                        lib.functions.push(ImportFunction { address: *record, ordinal: ordinal, thunk: 0 });
                    }
                    1 => {
                        if let Some(func) = lib.functions.last_mut() {
                            // println!("Record 0x{:08X}, ordinal 0x{:04X}, thunk 0x{:08X}", func.address, ordinal, *record);
                            func.thunk = *record;
                        }
                    }
                    _ => {} // shouldn't ever reach this branch, will always be 0 or 1
                }
            }
        }

        let mut num_imps = 0;
        let mut num_thunks = 0;
        let mut min_imp_addr: Option<u32> = None;
        let mut max_imp_addr: Option<u32> = None;
        let mut min_api_addr: Option<u32> = None;
        let mut max_api_addr: Option<u32> = None;
        let mut captured_imps: Vec<u32> = vec![];

        // to unstrip an __imp_,
        // swap the endianness of the last two bytes (so 00 01 01 90 becomes 90 01 00 00, we only care about the last two bytes)
        // then slap an 80 at the end (90 01 00 80) - the 80 tells the system that we're importing by ordinal
        fn unstrip_imp(imp: &mut [u8]){
            imp[0] = imp[3]; imp[1] = imp[2]; imp[2] = 0; imp[3] = 0x80;
        }
        fn add_imp(obj: &mut ObjInfo, name: String, addr: SectionAddress) -> Result<SymbolIndex> {
            return obj.add_symbol(ObjSymbol {
               name, address: addr.address as u64, section: Some(addr.section), size: 4, size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global | ObjSymbolFlags::Common), kind: ObjSymbolKind::Object, ..Default::default()
            }, false);
        }
        // to unstrip a thunk,
        // you need the address of the __imp_ (i.e. __imp_XamInputGetCapabilities at 0x827103c4)
        // then add it into the first two words via an lis/addi
        // (example: XamInputGetCapabilities: 01 00 01 90 02 00 01 90 7D 69 03 A6 4E 80 04 20)
        // (change the first two words to lis/addi r11 to 0x827103c4: 3D 60 82 71 81 6B 03 C4)
        // (then it becomes: 3D 60 82 71 81 6B 03 C4 7D 69 03 A6 4E 80 04 20)
        fn unstrip_thunk(thunk: &mut [u8], imp_addr: u32){
            thunk[0] = 0x3D; thunk[1] = 0x60;
            thunk[2] = ((imp_addr & 0xFF000000) >> 24) as u8;
            thunk[3] = ((imp_addr & 0xFF0000) >> 16) as u8;
            thunk[4] = 0x81; thunk[5] = 0x6B;
            thunk[6] = ((imp_addr & 0xFF00) >> 8) as u8;
            thunk[7] = (imp_addr & 0xFF) as u8;
        }
        fn add_thunk(obj: &mut ObjInfo, name: String, addr: SectionAddress) -> Result<SymbolIndex> {
            obj.known_functions.insert(addr, Some(0x10));
            return add_imp(obj, name, addr);
        }

        // now, process them (add funcs/symbols and unstrip)
        for lib in imports.libraries.iter(){
            // println!("Imports for {}:", lib.name);
            for func in lib.functions.iter() {
                // println!("  Func: addr 0x{:08X}, ordinal 0x{:04X}, thunk 0x{:08X}", func.address, func.ordinal, func.thunk);
                assert_ne!(func.address, 0, "Should not have an empty import func address!");
                min_imp_addr = Some(min_imp_addr.unwrap_or(func.address).min(func.address));
                max_imp_addr = Some(max_imp_addr.unwrap_or(func.address).max(func.address));

                let (sec_idx, sec) = obj.sections.at_address_mut(func.address)?;
                let lookup_name = replace_ordinal(&lib.name, func.ordinal as usize);
                let sym_name = format!("__imp_{}", lookup_name);

                let offset_within_sec: usize = func.address as usize - sec.address as usize;
                unstrip_imp(&mut sec.data[offset_within_sec..offset_within_sec + 4]);
                // println!("  Adding symbol {} at 0x{:08X}", sym_name, func.address);
                add_imp(&mut obj, sym_name, SectionAddress::new(sec_idx, func.address))?;
                captured_imps.push(func.address);
                num_imps += 1;
                
                if func.thunk != 0 {
                    min_api_addr = Some(min_api_addr.unwrap_or(func.thunk).min(func.thunk));
                    max_api_addr = Some(max_api_addr.unwrap_or(func.thunk).max(func.thunk));
                    // println!("thunk at 0x{:08X}", func.thunk);
                    // create a symbol/func for the thunk - will always be size 0x10
                    let (thunk_idx, thunk_sec) = obj.sections.at_address_mut(func.thunk)?;
                    let offset_within_sec: usize = func.thunk as usize - thunk_sec.address as usize;
                    unstrip_thunk(&mut thunk_sec.data[offset_within_sec..offset_within_sec + 8], func.address);
                    // println!("  Adding symbol {} at 0x{:08X}", thunk_name, func.thunk);
                    add_thunk(&mut obj, lookup_name, SectionAddress::new(thunk_idx, func.thunk))?;
                    num_thunks += 1;
                }
            }
        }

        // for SOME reason, microsoft can have imports/thunks that aren't referenced in the import libraries
        // but can be referenced in xidata later on
        // so, this block of code serves to search for and capture them
        if min_imp_addr.is_some() && max_imp_addr.is_some() {
            let min_addr = min_imp_addr.unwrap();
            let max_addr = max_imp_addr.unwrap();

            // i had to write things this way because of how rust handles borrowing...thank you rust, very cool
            let (import_idx, offset_within_sec) = {
                let (idx, sec) = obj.sections.at_address(min_addr)?;
                (idx, (min_addr - sec.address as u32) as usize)
            };
            let mut i = min_addr;
            loop {
                let data_idx = offset_within_sec + (i - min_addr) as usize;
                let cur_imp = {
                    let sec = &obj.sections[import_idx];
                    if data_idx >= sec.data.len() { break; }
                    read_word(&sec.data, data_idx)
                };
                if i > max_addr && cur_imp == 0 { break; }

                if cur_imp != 0 && !captured_imps.contains(&i){
                    let sym_name = format!("__imp_{}",
                                           replace_ordinal(&imports.libraries[((cur_imp & 0x00FF0000) >> 16) as usize].name, (cur_imp & 0xFFFF) as usize));
                    // println!("Found missing imp {} at 0x{:08X}", sym_name, i);
                    {
                        // obj borrowing scope moment
                        let sec = &mut obj.sections[import_idx];
                        unstrip_imp(&mut sec.data[data_idx..data_idx + 4]);
                    }
                    add_imp(&mut obj, sym_name, SectionAddress::new(import_idx, i))?;
                    num_imps += 1;
                }

                i += 4;
            }
        }
        if min_api_addr.is_some() && max_api_addr.is_some() {
            let min_addr = min_api_addr.unwrap();
            let max_addr = max_api_addr.unwrap();

            // i had to write things this way because of how rust handles borrowing...thank you rust, very cool
            let (thunk_idx, offset_within_sec) = {
                let (idx, sec) = obj.sections.at_address(min_addr)?;
                (idx, (min_addr - sec.address as u32) as usize)
            };

            let mut i = min_addr;
            loop {
                let data_idx = offset_within_sec + (i - min_addr) as usize;
                let cur_thunk = {
                    let sec = &obj.sections[thunk_idx];
                    if data_idx >= sec.data.len() { break; }
                    read_word(&sec.data, data_idx)
                };
                if i > max_addr && cur_thunk == 0 { break; }
                else if i < max_addr && cur_thunk == 0 {
                    i += 4; continue;
                }

                if cur_thunk != 0 {
                    let cur_addr = SectionAddress::new(thunk_idx, i);
                    if !obj.known_functions.contains_key(&cur_addr){
                        let sym_name = replace_ordinal(&imports.libraries[((cur_thunk & 0x00FF0000) >> 16) as usize].name, (cur_thunk & 0xFFFF) as usize);
                        // println!("Found missing thunk {} at 0x{:08X}", sym_name, i);
                        let imp_name = format!("__imp_{}",sym_name);
                        let maybe_imp_sym = obj.symbols.by_name(&imp_name)?;
                        if maybe_imp_sym.is_some(){
                            // println!("found sym {}", maybe_imp_sym.unwrap().1.name);
                            unstrip_thunk(&mut obj.sections[thunk_idx].data[data_idx..data_idx + 8], maybe_imp_sym.unwrap().1.address as u32);
                        }
                        add_thunk(&mut obj, sym_name, cur_addr)?;
                        num_thunks += 1;
                    }
                }
                i += 0x10;
            }
        }
        log::info!("Found {} imps and {} import thunks from import data!", num_imps, num_thunks);
    }

    // add known function boundaries from pdata
    // pdata info: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
    let (_pdata_idx, pdata_section) = match obj.sections.by_name(".pdata")? {
        Some(the_pair) => the_pair,
        None => { return Err(anyhow!(".pdata section not found. Is that even possible for an xex?")) }
    };
    let (text_idx, _text_section) = match obj.sections.by_name(".text")? {
        Some(the_pair) => the_pair,
        None => { return Err(anyhow!(".text section not found...how did we even get to this point?"))}
    };

    let mut num = 0;
    for (_, chunk) in pdata_section.data.chunks_exact(8).enumerate(){
        let start_addr = u32::from_be_bytes(chunk[0..4].try_into()?);
        // if we encounter 0's, that's the end of usable pdata entries
        if start_addr == 0 { break; }

        // some metadata for this function, including function size
        let word = u32::from_be_bytes(chunk[4..8].try_into()?);
        // let num_prologue_insts = word & 0xFF; // The number of instructions in the function's prolog.
        let num_insts_in_func = (word >> 8) & 0x3FFFFF; // The number of instructions in the function.
        // let flag_32bit = (word & 0x4000) != 0; // If set, the function consists of 32-bit instructions. If clear, the function consists of 16-bit instructions.
        // let exception_flag = (word & 0x8000) != 0; // If set, an exception handler exists for the function. Otherwise, no exception handler exists.

        let section_addr = SectionAddress::new(text_idx, start_addr);
        obj.known_functions.insert(section_addr, Some(num_insts_in_func * 4));
        obj.pdata_funcs.push(section_addr);
        // println!("Func at 0x{:08X} has prologue length 0x{:06X}", start_addr, num_prologue_insts);
        num += 1;
    }
    log::info!("Found {} known funcs from pdata!", num);

    // if this xex has an .xidata section, mark down the funcs in there
    if let Some(xidata_pair) = obj.sections.by_name(".xidata")? {
        let xidata_idx = xidata_pair.0;
        let xidata_sec = xidata_pair.1;

        let mut num_xidatas = 0;
        for (i, chunk) in xidata_sec.data.chunks_exact(16).enumerate(){
            if i == 0 { continue; } // the first entry appears to be all 0's...but is every xidata like this?
            let inst1 = u32::from_be_bytes(chunk[0..4].try_into()?);
            // if we've reached 0's, that's the end of usable xidata info
            if inst1 == 0 { break; }

            assert_eq!(inst1 & 0xFFFF0000, 0x3D600000, "First instruction MUST be an lis to r11!");
            let inst2 = u32::from_be_bytes(chunk[4..8].try_into()?);
            assert_eq!(inst2 & 0xFFFF0000, 0x396B0000, "Second instruction MUST be an addi to r11!");
            assert_eq!(u32::from_be_bytes(chunk[8..12].try_into()?), 0x7d6903a6, "Third instruction MUST be mtspr CTR, r11!");
            assert_eq!(u32::from_be_bytes(chunk[12..16].try_into()?), 0x4e800420, "Fourth and final instruction MUST be bctr!");

            let func_addr = (xidata_sec.address as usize + (i * 16)) as u32;
            // println!("This xidata func's address: 0x{:08X}", func_addr);
            obj.known_functions.insert(SectionAddress::new(xidata_idx, func_addr), Some(0x10));
            num_xidatas += 1;
        }
        log::info!("Found {} known funcs from xidata!", num_xidatas);
    }

    // .XBMOVIE: matches up with ground truth...but it's mostly a sea of 0's
    // .idata: partially zero'ed out and offsetted from ground truth in debug, completely gone from release
    //      xidata/its relevant info seems to be covered, making idata a non-issue...i guess?
    // .XBLD: zero'ed out in debug, completely gone from release
    // .reloc: zero'ed out regardless

    Ok(obj)
}

// debug only, lists section bounds
fn list_exe_sections(exe: &PeFile32){
    println!("Sections:");
    for sec in exe.section_table().iter(){
        let name = std::str::from_utf8(&sec.name)
            .unwrap_or("")
            .trim_end_matches('\0');
        println!("Name: {}", name);
        println!("  VirtualSize: 0x{:08X}", sec.virtual_size.get(endian::LittleEndian));
        println!("  VirtualAddress: 0x{:08X}", sec.virtual_address.get(endian::LittleEndian));
        println!("  SizeOfRawData: 0x{:08X}", sec.size_of_raw_data.get(endian::LittleEndian));
        println!("  PointerToRawData: 0x{:08X}", sec.pointer_to_raw_data.get(endian::LittleEndian));
        println!("  Has uninitialized data? {}", sec.characteristics.get(endian::LittleEndian) & 0x80 != 0);
        println!("");
    }
}