use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
};

use anyhow::{bail, ensure, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::obj::{ObjSymbol, ObjSymbolKind};

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

const MAGIC: &[u8] = "CodeWarrior".as_bytes();
const PADDING: &[u8] = &[0u8; 0x16];

impl MWComment {
    pub fn parse_header<R: Read + Seek>(reader: &mut R) -> Result<MWComment> {
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
        let mut magic = vec![0u8; MAGIC.len()];
        reader.read_exact(&mut magic).context("While reading magic")?;
        if magic.deref() != MAGIC {
            bail!("Invalid .comment section magic: {:?}", magic);
        }
        // 0xB
        header.version = reader.read_u8()?;
        ensure!(
            matches!(header.version, 8 | 10 | 11 | 13 | 14 | 15),
            "Unknown .comment section version: {}",
            header.version
        );
        // 0xC - 0xF
        reader
            .read_exact(&mut header.compiler_version)
            .context("While reading compiler version")?;
        // 0x10
        header.pool_data = match reader.read_u8()? {
            0 => false,
            1 => true,
            value => bail!("Invalid value for pool_data: {}", value),
        };
        // 0x11
        header.float =
            MWFloatKind::try_from(reader.read_u8()?).context("Invalid value for float")?;
        // 0x12 - 0x13
        header.processor = reader.read_u16::<BigEndian>()?;
        // 0x14
        match reader.read_u8()? as char {
            // This is 0x2C, which could also be the size of the header? Unclear
            ',' => {}
            c => bail!("Expected ',' after processor, got '{}'", c),
        }
        // 0x15
        let flags = reader.read_u8()?;
        if flags & !7 != 0 {
            bail!("Unexpected flag value {:#X}", flags);
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
        reader.seek(SeekFrom::Current(0x16))?;
        Ok(header)
    }

    pub fn write_header<W: Write>(&self, w: &mut W) -> Result<()> {
        // 0x0 - 0xA
        w.write_all(MAGIC)?;
        // 0xB
        w.write_u8(self.version)?;
        // 0xC - 0xF
        w.write_all(&self.compiler_version)?;
        // 0x10
        w.write_u8(if self.pool_data { 1 } else { 0 })?;
        // 0x11
        w.write_u8(self.float.into())?;
        // 0x12 - 0x13
        w.write_u16::<BigEndian>(self.processor)?;
        // 0x14
        w.write_u8(0x2C)?;
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
        w.write_u8(flags)?;
        // 0x16 - 0x2C
        w.write_all(PADDING)?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CommentSym {
    pub align: u32,
    pub vis_flags: u8,
    pub active_flags: u8,
}

impl CommentSym {
    pub fn from(symbol: &ObjSymbol) -> Self {
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
        if symbol.flags.is_force_active() {
            active_flags |= 0x8; // TODO what is 0x10?
        }
        Self { align, vis_flags, active_flags }
    }
}

pub fn write_comment_sym<W: Write>(w: &mut W, symbol: CommentSym) -> Result<()> {
    w.write_u32::<BigEndian>(symbol.align)?;
    w.write_u8(symbol.vis_flags)?;
    w.write_u8(symbol.active_flags)?;
    w.write_u8(0)?;
    w.write_u8(0)?;
    Ok(())
}

pub fn read_comment_sym<R: Read>(r: &mut R) -> Result<CommentSym> {
    let mut out = CommentSym { align: 0, vis_flags: 0, active_flags: 0 };
    out.align = r.read_u32::<BigEndian>()?;
    out.vis_flags = r.read_u8()?;
    ensure!(matches!(out.vis_flags, 0 | 0xD | 0xE), "Unknown vis_flags {}", out.vis_flags);
    out.active_flags = r.read_u8()?;
    ensure!(
        matches!(out.active_flags, 0 | 0x8 | 0x10 | 0x20),
        "Unknown active_flags {}",
        out.active_flags
    );
    ensure!(r.read_u8()? == 0, "Unexpected value after active_flags (1)");
    ensure!(r.read_u8()? == 0, "Unexpected value after active_flags (2)");
    Ok(out)
}
