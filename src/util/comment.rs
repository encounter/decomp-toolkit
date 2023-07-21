use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
};

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::obj::{ObjSymbol, ObjSymbolFlags, ObjSymbolKind};

#[derive(Debug, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum MWFloatKind {
    None = 0,
    Soft = 1,
    Hard = 2,
}

#[derive(Debug, Clone)]
pub struct MWComment {
    pub compiler_version: [u8; 4],
    pub pool_data: bool,
    pub float: MWFloatKind,
    pub processor: u16,
    pub incompatible_return_small_structs: bool,
    pub incompatible_sfpe_double_params: bool,
    pub unsafe_global_reg_vars: bool,
}

impl Default for MWComment {
    fn default() -> Self {
        Self {
            // Metrowerks C/C++ Compiler for Embedded PowerPC
            // Version 2.4.2 build 81
            // (CodeWarrior for GameCube 1.3.2)
            compiler_version: [2, 4, 2, 1],
            pool_data: true,
            float: MWFloatKind::Hard,
            processor: 0x16, // gekko
            incompatible_return_small_structs: false,
            incompatible_sfpe_double_params: false,
            unsafe_global_reg_vars: false,
        }
    }
}

const MAGIC: &[u8] = "CodeWarrior\n".as_bytes();
const PADDING: &[u8] = &[0u8; 0x16];

impl MWComment {
    pub fn parse_header<R: Read + Seek>(reader: &mut R) -> Result<MWComment> {
        let mut header = MWComment {
            compiler_version: [0; 4],
            pool_data: false,
            float: MWFloatKind::None,
            processor: 0,
            incompatible_return_small_structs: false,
            incompatible_sfpe_double_params: false,
            unsafe_global_reg_vars: false,
        };
        // 0x0 - 0xB
        let mut magic = vec![0u8; MAGIC.len()];
        reader.read_exact(&mut magic).context("While reading magic")?;
        if magic.deref() != MAGIC {
            bail!("Invalid comment section magic: {:?}", magic);
        }
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
        w.write_all(MAGIC)?;
        w.write_all(&self.compiler_version)?;
        w.write_u8(if self.pool_data { 1 } else { 0 })?;
        w.write_u8(self.float.into())?;
        w.write_u16::<BigEndian>(self.processor)?;
        w.write_u8(0x2C)?;
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
        w.write_all(PADDING)?;
        Ok(())
    }
}

pub fn write_comment_sym<W: Write>(w: &mut W, symbol: &ObjSymbol) -> Result<()> {
    let align = match symbol.align {
        Some(align) => align,
        None => {
            if symbol.flags.0.contains(ObjSymbolFlags::Common) {
                symbol.address as u32
            } else {
                match symbol.kind {
                    ObjSymbolKind::Unknown => 0,
                    ObjSymbolKind::Function => 4,
                    ObjSymbolKind::Object => 4,
                    ObjSymbolKind::Section => 8, // TODO?
                }
            }
        }
    };
    w.write_u32::<BigEndian>(align)?;
    let mut vis_flags = 0;
    if symbol.flags.0.contains(ObjSymbolFlags::Weak) {
        vis_flags |= 0xE; // TODO 0xD?
    }
    w.write_u8(vis_flags)?;
    let mut active_flags = 0;
    if symbol.flags.0.contains(ObjSymbolFlags::ForceActive) {
        active_flags |= 8;
    }
    w.write_u8(active_flags)?;
    w.write_u8(0)?;
    w.write_u8(0)?;
    Ok(())
}
