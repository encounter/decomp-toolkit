use std::{
    borrow::Cow, collections::{hash_map, HashMap}, fs, io::Cursor, num::NonZeroU64, path::Path
};

use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use itertools::Itertools;
use object::{
    endian, read::pe::{PeFile32, PeFile64}, Architecture, BinaryFormat, Endianness, File, Import, Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget, SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection
};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    analysis::cfa::SectionAddress, array_ref, obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    }, util::{
        comment::{CommentSym, MWComment}, crypto::decrypt_aes128_cbc_no_padding, reader::{Endian, FromReader, ToWriter}
    }
};

use num_enum::{ TryFromPrimitive, IntoPrimitive };

// quick and ez ways to read data from a block of bytes
pub fn read_halfword(data: &Vec<u8>, index: usize) -> u16 {
    return u16::from_be_bytes([data[index], data[index + 1]]);
}

pub fn read_word(data: &Vec<u8>, index: usize) -> u32 {
    return u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
}

#[derive(thiserror::Error, Debug)]
pub enum XexError {
    #[error("XEX2 header not found!")]
    HeaderNotFound,
    #[error("No data found in optional header!")]
    HeaderDataNotFound,
    #[error("Import library must have an even number of records!")]
    InvalidLibRecordCount,
    #[error("Resource info has unexpected length! (expected 16)")]
    InvalidResourceInfoLength,
    #[error("Xex has unhandled compression type!")]
    UnhandledCompressionType,
    #[error("Xex has unhandled encryption type!")]
    UnhandledEncryptionType,
    #[error("Could not derive session key!")]
    InvalidSessionKey,
    #[error("Base file format not found!")]
    BaseFileFormatNotFound,
    #[error("Could not deduce exe type!")]
    InvalidExeType,
    #[error("Could not extract exe!")]
    ExeExtractionFailed
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

pub struct BaseFileFormat {
    pub encryption: u16, // 0 = no, 1 = yes
    pub compression: u16, // 0 = none, 1 = raw, 2 = compressed, 3 = delta compressed
    pub basics: Vec<BasicCompression>,
    pub normal: Option<NormalCompression>
}

impl BaseFileFormat {
    fn parse(data: &Vec<u8>) -> Result<Self, XexError> {
        let encryption = read_halfword(&data, 0);
        let compression = read_halfword(&data, 2);
        let mut basics: Vec<BasicCompression> = vec![];
        let mut normal = None;
        match compression {
            // none
            0 => {}
            // raw
            1 => {
                let count = (data.len() / 8) - 1;
                for i in 0..count {
                    basics.push(BasicCompression { data_size: read_word(&data, 4 + i * 8), zero_size: read_word(&data, 8 + i * 8) });
                }
            }
            // compressed or delta compressed
            2 | 3 => {
                normal = Some(NormalCompression { window_size: read_word(&data, 4), block_size: read_word(&data, 8), block_hash: data[12..32].try_into().unwrap() });
            }
            _ => { return Err(XexError::UnhandledCompressionType); }
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
    fn parse(data: &Vec<u8>) -> Result<Self, XexError> {
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
        for n in 0..lib_count {
            pos += 0x24;
            let name_idx = read_halfword(&data, pos) as usize;
            let count = read_halfword(&data, pos + 2) as usize;
            // for each record pair, first = __imp__API, second = the actual API
            // scratch that, DC3 has an odd number...dunno what for yet, but it does
            // if count % 2 != 0 {
            //     return Err(XexError::InvalidLibRecordCount);
            // }
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
    pub fn parse(data: &Vec<u8>) -> Result<Self, XexError> {
        if data.len() != 16 {
            return Err(XexError::InvalidResourceInfoLength);
        }
        let title_id = String::from_utf8(data[0..8].to_vec()).ok().unwrap();
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
        let mut file_timestamp = 0;
        let mut import_libs = None;
        let mut resource_info = None;
        let mut base_file_format = None;
        let mut static_libs: Vec<StaticLibrary> = vec![];

        // and now, process them
        for header in opt_headers {
            if header.data.is_empty() {
                return Err(XexError::HeaderDataNotFound);
            }
            match header.id {
                XexOptionalHeaderID::ResourceInfo => {
                    resource_info = Some(ResourceInfo::parse(&header.data)?);
                }
                XexOptionalHeaderID::BaseFileFormat => {
                    base_file_format = Some(BaseFileFormat::parse(&header.data)?);
                }
                XexOptionalHeaderID::DeltaPatchDescriptor => {
                    log::info!("TODO: handle patch descriptor");
                }
                XexOptionalHeaderID::BoundingPath => {
                    log::info!("TODO: handle bounding path");
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
                    original_name = String::from_utf8(header.data.clone()).ok().unwrap();
                }
                XexOptionalHeaderID::ChecksumTimestamp => {
                    file_timestamp = read_word(&header.data, 0);
                }
                XexOptionalHeaderID::StaticLibraries => {
                    let num_libs = header.data.len() / 16;
                    for i in 0..num_libs {
                        let start = i * 16;
                        static_libs.push(StaticLibrary {
                            name: String::from_utf8(header.data[start..start + 8].to_vec()).ok().unwrap(),
                            major: read_halfword(&header.data, start + 8),
                            minor: read_halfword(&header.data, start + 10),
                            build: read_halfword(&header.data, start + 12),
                            qfe: header.data[start + 15],
                            approval_type: header.data[start + 14]
                        });
                    }
                }
                _ => {
                    log::info!("unhandled header ID {:?}", header.id);
                }
            }
        }
        // at the very minimum, we should have a base file format, as that contains encryption/compression information
        if base_file_format.is_none() {
            return Err(XexError::BaseFileFormatNotFound);
        }
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
    fn parse(data: &Vec<u8>, security_offset: u32) -> Result<Self, XexError> {
        let mut pos = security_offset as usize;
        let header_size = read_word(&data, pos);
        let image_size = read_word(&data, pos + 4);
        pos += 8;
        let rsa_signature = data[pos..pos + 256].try_into().unwrap();
        pos += 256;
        let unknown = read_word(&data, pos);
        let image_flags = read_word(&data, pos + 4);
        let load_address = read_word(&data, pos + 8);
        pos += 12;
        let section_digest = data[pos..pos + 20].try_into().unwrap();
        pos += 20;
        let import_table_count = read_word(&data, pos);
        pos += 4;
        let import_table_digest = data[pos..pos + 20].try_into().unwrap();
        pos += 20;
        let media_id = data[pos..pos + 16].try_into().unwrap();
        pos += 16;
        let file_key = data[pos..pos + 16].try_into().unwrap();
        pos += 16;
        let export_table = read_word(&data, pos);
        pos += 4;
        let header_digest = data[pos..pos + 20].try_into().unwrap();
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
    fn derive_keys(file_key: &[u8; 16]) -> Result<Self, XexError> {
        let retail_derived_key: [u8; 16] = match decrypt_aes128_cbc_no_padding(&RETAIL_KEY, file_key){
            Ok(the_key) => { the_key.try_into().unwrap()},
            Err(e) => return Err(XexError::InvalidSessionKey),
        };

        let devkit_derived_key: [u8; 16] = match decrypt_aes128_cbc_no_padding(&DEVKIT_KEY, file_key){
            Ok(the_key) => { the_key.try_into().unwrap()},
            Err(e) => return Err(XexError::InvalidSessionKey),
        };

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

const MODULE_FLAGS: [&str; 8] = [ "Title Module", "Exports To Title", "System Debugger", "DLL Module", "Module Patch", "Patch Full", "Patch Delta", "User Mode" ];

pub struct XexInfo {
    pub raw_bytes: Vec<u8>,
    pub header: XexHeader,
    pub opt_header_data: XexOptionalHeaderData,
    pub loader_info: XexLoaderInfo,
    pub session_key: [u8; 16],
    pub is_dev_kit: bool,
}

impl XexInfo {
    pub fn from_file(path: &Utf8NativePathBuf) -> Result<Self, XexError> {
        let std_path = path.to_path_buf();
        let data = fs::read(std_path).expect("Failed to read file");

        let xex_header = XexHeader::parse(&data)?;
        let xex_optional_header_data = XexOptionalHeaderData::parse(&data)?;
        let xex_loader_info = XexLoaderInfo::parse(&data, xex_header.security_info_offset)?;
        let xex_session_keys = XexSessionKeys::derive_keys(&xex_loader_info.file_key)?;
        let confirmed_session_key: [u8; 16];
        let is_dev_kit: bool;

        // this is where we'd parse xexsection related info...but it might not be needed?

        // Since we have the possible session keys at this point,
        // try to retrieve the first 2 bytes of the exe and check for "MZ"
        let pe_vec = data[xex_header.pe_offset as usize..data.len()].to_vec();
        let compressed_retail: Cow<[u8]>;
        let compressed_devkit: Cow<[u8]>;
        let bff = xex_optional_header_data.base_file_format.as_ref().unwrap();

        match bff.encryption {
            // not encrypted
            0 => {
                // if unencrypted, can we assume devkit?
                compressed_retail = Cow::Borrowed(&pe_vec);
                compressed_devkit = Cow::Borrowed(&pe_vec);
            }
            // encrypted
            1 => {
                compressed_retail = Cow::Owned(
                    decrypt_aes128_cbc_no_padding(
                        &xex_session_keys.session_key_retail, &pe_vec
                    ).map_err(|_| XexError::InvalidSessionKey)?
                );
                compressed_devkit = Cow::Owned(
                    decrypt_aes128_cbc_no_padding(
                        &xex_session_keys.session_key_devkit, &pe_vec
                    ).map_err(|_| XexError::InvalidSessionKey)?
                );
            }
            _ => { return Err(XexError::UnhandledEncryptionType); }
        }
        
        // we're only checking the first two bytes
        let mut retail_bytes: [u8; 2] = [ 0, 0 ];
        let mut devkit_bytes: [u8; 2] = [ 0, 0 ];
        
        match bff.compression {
            1 => {
                let mut pos_in: usize = 0;
                let mut pos_out: usize = 0;
                let mut should_break = false;
                for bc in &bff.basics {
                    for i in 0..(bc.data_size as usize) {
                        if pos_in + i >= compressed_retail.len() { break; } 
                        if (i + pos_out >= 2) || (i + pos_in >= 2) {
                            should_break = true;
                            break;
                        }
                        retail_bytes[i + pos_out] = compressed_retail[pos_in + i];
                        devkit_bytes[i + pos_out] = compressed_devkit[pos_in + i];
                    }
                    pos_out += (bc.data_size + bc.zero_size) as usize;
                    pos_in += bc.data_size as usize;
                    if should_break { break; }
                }
            }
            0 | 3 => {
                retail_bytes = compressed_retail[0..2].try_into().unwrap();
                devkit_bytes = compressed_devkit[0..2].try_into().unwrap();
            }
            2 => {
                println!("TODO: handle case 2");
                return Err(XexError::UnhandledCompressionType);
            }
            _ => { return Err(XexError::UnhandledCompressionType); }
        }

        if retail_bytes[0] == 'M' as u8 && retail_bytes[1] == 'Z' as u8 {
            // println!("This xex was built in retail mode!");
            confirmed_session_key = xex_session_keys.session_key_retail;
            is_dev_kit = false;
        }
        else if devkit_bytes[0] == 'M' as u8 && devkit_bytes[1] == 'Z' as u8 {
            // println!("This xex was built in devkit mode!");
            confirmed_session_key = xex_session_keys.session_key_devkit;
            is_dev_kit = true;
        }
        else {
            return Err(XexError::InvalidExeType);
        }

        return Ok(Self {
            raw_bytes: data,
            header: xex_header,
            opt_header_data:xex_optional_header_data,
            loader_info: xex_loader_info,
            session_key: confirmed_session_key,
            is_dev_kit: is_dev_kit
        });
    }

    pub fn get_exe(&self) -> Result<Vec<u8>, XexError> {
        assert!(!&self.raw_bytes.is_empty());
        
        let pe_vec = &self.raw_bytes[self.header.pe_offset as usize..self.raw_bytes.len()].to_vec();
        let compressed: Cow<[u8]>;
        let bff = &self.opt_header_data.base_file_format.as_ref().unwrap();

        match bff.encryption {
            // not encrypted
            0 => { compressed = Cow::Borrowed(&pe_vec); }
            // encrypted
            1 => {
                compressed = Cow::Owned(
                    decrypt_aes128_cbc_no_padding(&self.session_key, &pe_vec)
                    .map_err(|_| XexError::InvalidSessionKey)?
                );
            }
            _ => { return Err(XexError::UnhandledEncryptionType); }
        }
        let mut pe_image: Vec<u8> = vec![];
        pe_image.resize(self.loader_info.image_size as usize, 0);
        let mut pos_in: usize = 0;
        let mut pos_out: usize = 0;
        match bff.compression {
            1 => {
                for bc in &bff.basics {
                    for i in 0..(bc.data_size as usize) {
                        if pos_in + i as usize >= compressed.len() { break; }
                        pe_image[i + pos_out] = compressed[pos_in + i];
                    }
                    pos_out += (bc.data_size + bc.zero_size) as usize;
                    pos_in += bc.data_size as usize;
                }
            }
            0 | 3 => { pe_image = compressed.to_vec(); }
            2 => {
                println!("TODO: handle case 2");
                return Err(XexError::UnhandledCompressionType);
            }
            _ => { return Err(XexError::UnhandledCompressionType); }
        }

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

pub fn extract_exe(input: &Utf8NativePathBuf) -> Result<Vec<u8>, XexError> {
    println!("xex: {input}");
    let xex = XexInfo::from_file(input)?;
    // after this line, the XexInfo should have all of its relevant metadata parsed
    // so, try to read the PE image
    return xex.get_exe();
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