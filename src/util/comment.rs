use std::{
    io,
    io::{Read, Seek, Write},
};

use anyhow::{bail, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tracing::warn;

use crate::{
    obj::{ObjSymbol, ObjSymbolKind},
    util::reader::{skip_bytes, struct_size, Endian, FromReader, ToWriter},
};

#[derive(Debug, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum MWFloatKind {
    None = 0,
    Soft = 1,
    Hard = 2,
}

#[derive(Debug, Clone)]
pub struct MWComment {
    pub version: u8,
    pub compiler_version: [u8; 4],
    pub pool_data: bool,
    pub float: MWFloatKind,
    pub processor: u16,
    pub incompatible_return_small_structs: bool,
    pub incompatible_sfpe_double_params: bool,
    pub unsafe_global_reg_vars: bool,
}

const MAGIC: &[u8] = "CodeWarrior".as_bytes();
const HEADER_SIZE: u8 = 0x2C;
const PADDING: &[u8] = &[0u8; 0x16];

impl FromReader for MWComment {
    type Args = ();

    const STATIC_SIZE: usize = HEADER_SIZE as usize;

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let mut header = MWComment {
            version: 0,
            compiler_version: [0; 4],
            pool_data: false,
            float: MWFloatKind::None,
            processor: 0,
            incompatible_return_small_structs: false,
            incompatible_sfpe_double_params: false,
            unsafe_global_reg_vars: false,
        };
        // 0x0 - 0xA
        let magic = <[u8; MAGIC.len()]>::from_reader(reader, e)?;
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid .comment section magic: {magic:?}"),
            ));
        }
        // 0xB
        header.version = u8::from_reader(reader, e)?;
        if !matches!(header.version, 8 | 10 | 11 | 13 | 14 | 15) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown .comment section version: {}", header.version),
            ));
        }
        // 0xC - 0xF
        reader.read_exact(&mut header.compiler_version)?;
        // 0x10
        header.pool_data = match u8::from_reader(reader, e)? {
            0 => false,
            1 => true,
            value => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid value for pool_data: {value}"),
                ))
            }
        };
        // 0x11
        header.float = MWFloatKind::try_from(u8::from_reader(reader, e)?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid value for float"))?;
        // 0x12 - 0x13
        header.processor = u16::from_reader(reader, e)?;
        // 0x14
        match u8::from_reader(reader, e)? {
            HEADER_SIZE => {}
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Expected header size {HEADER_SIZE:#X}, got {v:#X}"),
                ))
            }
        }
        // 0x15
        let flags = u8::from_reader(reader, e)?;
        if flags & !7 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected flag value {flags:#X}"),
            ));
        }
        if flags & 1 == 1 {
            header.incompatible_return_small_structs = true;
        }
        if flags & 2 == 2 {
            header.incompatible_sfpe_double_params = true;
        }
        if flags & 4 == 4 {
            header.unsafe_global_reg_vars = true;
        }
        // 0x16 - 0x2C
        skip_bytes::<0x16, _>(reader)?;
        Ok(header)
    }
}

impl ToWriter for MWComment {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        // 0x0 - 0xA
        MAGIC.to_writer(writer, e)?;
        // 0xB
        self.version.to_writer(writer, e)?;
        // 0xC - 0xF
        self.compiler_version.to_writer(writer, e)?;
        // 0x10
        (if self.pool_data { 1u8 } else { 0u8 }).to_writer(writer, e)?;
        // 0x11
        u8::from(self.float).to_writer(writer, e)?;
        // 0x12 - 0x13
        self.processor.to_writer(writer, e)?;
        // 0x14
        HEADER_SIZE.to_writer(writer, e)?;
        // 0x15
        let mut flags = 0u8;
        if self.incompatible_return_small_structs {
            flags |= 1;
        }
        if self.incompatible_sfpe_double_params {
            flags |= 2;
        }
        if self.unsafe_global_reg_vars {
            flags |= 4;
        }
        flags.to_writer(writer, e)?;
        // 0x16 - 0x2C
        PADDING.to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl MWComment {
    pub fn new(version: u8) -> Result<Self> {
        // Metrowerks C/C++ Compiler for Embedded PowerPC.
        let compiler_version = match version {
            // Version 2.3.3 build 144
            // (CodeWarrior for GameCube 1.0)
            8 => [2, 3, 0, 1],
            // Version 2.4.2 build 81
            // (CodeWarrior for GameCube 1.3.2)
            10 => [2, 4, 2, 1],
            // Version 2.4.7 build 108
            // (CodeWarrior for GameCube 2.7)
            11 | 13 => [2, 4, 7, 1],
            // Version 4.1 build 60126
            // (CodeWarrior for GameCube 3.0 Alpha 3)
            14 | 15 => [4, 0, 0, 1],
            _ => bail!("Unsupported MW .comment version {version}"),
        };
        Ok(Self {
            version,
            compiler_version,
            pool_data: true,
            float: MWFloatKind::Hard,
            processor: 0x16, // gekko
            incompatible_return_small_structs: false,
            incompatible_sfpe_double_params: false,
            unsafe_global_reg_vars: false,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CommentSym {
    pub align: u32,
    pub vis_flags: u8,
    pub active_flags: u8,
}

impl FromReader for CommentSym {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // align
        u8::STATIC_SIZE,  // vis_flags
        u8::STATIC_SIZE,  // active_flags
        2,                // padding
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let mut out = CommentSym { align: 0, vis_flags: 0, active_flags: 0 };
        out.align = u32::from_reader(reader, e)?;
        out.vis_flags = u8::from_reader(reader, e)?;
        if !matches!(out.vis_flags, 0 | 0xD | 0xE) {
            warn!("Unknown vis_flags: {:#X}", out.vis_flags);
        }
        out.active_flags = u8::from_reader(reader, e)?;
        if !matches!(out.active_flags, 0 | 0x8 | 0x10 | 0x20) {
            warn!("Unknown active_flags: {:#X}", out.active_flags);
        }
        let value = u8::from_reader(reader, e)?;
        if value != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected value after active_flags (1): {value:#X}"),
            ));
        }
        let value = u8::from_reader(reader, e)?;
        if value != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected value after active_flags (2): {value:#X}"),
            ));
        }
        Ok(out)
    }
}

impl ToWriter for CommentSym {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        self.align.to_writer(writer, e)?;
        self.vis_flags.to_writer(writer, e)?;
        self.active_flags.to_writer(writer, e)?;
        [0u8; 2].to_writer(writer, e)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl CommentSym {
    pub fn from(symbol: &ObjSymbol, export_all: bool) -> Self {
        let align = match symbol.align {
            Some(align) => align,
            None => {
                if symbol.flags.is_common() {
                    symbol.address as u32
                } else {
                    match symbol.kind {
                        ObjSymbolKind::Unknown => 0,
                        ObjSymbolKind::Function => 4,
                        ObjSymbolKind::Object => {
                            if symbol.address & 3 == 0 {
                                4
                            } else {
                                1
                            }
                        }
                        ObjSymbolKind::Section => 8,
                    }
                }
            }
        };
        let mut vis_flags = 0;
        if symbol.flags.is_weak() {
            vis_flags |= 0xD;
        }
        let mut active_flags = 0;
        if !symbol.flags.is_stripped()
            && (symbol.flags.is_exported()
                || (export_all
                    && !symbol.flags.is_no_export()
                    && matches!(symbol.kind, ObjSymbolKind::Function | ObjSymbolKind::Object)))
        {
            active_flags |= 0x8;
        }
        Self { align, vis_flags, active_flags }
    }
}
