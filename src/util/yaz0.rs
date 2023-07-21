// Source: https://github.com/Julgodis/picori/blob/650da9f4fe6050b39b80d5360416591c748058d5/src/yaz0.rs
// License: MIT
// Modified to use `std::io::Read`/`Seek` and `byteorder`
use std::io::{Read, Seek};

use anyhow::{ensure, Result};
use byteorder::{BigEndian, ReadBytesExt};

/// Yaz0 header.
pub struct Header {
    /// Yaz0 magic (0x59617A30).
    pub magic: u32,
    /// Size of decompressed data.
    pub decompressed_size: u32,
    _reserved0: u32,
    _reserved1: u32,
}

impl Header {
    /// Reads a Yaz0 header from a reader.
    pub fn from_binary<D: Read>(input: &mut D) -> Result<Header> {
        Ok(Header {
            magic: input.read_u32::<BigEndian>()?,
            decompressed_size: input.read_u32::<BigEndian>()?,
            _reserved0: input.read_u32::<BigEndian>()?,
            _reserved1: input.read_u32::<BigEndian>()?,
        })
    }

    /// Checks if the header is valid.
    pub fn is_valid(&self) -> bool { self.magic == 0x59617A30 }

    pub fn decompressed_size(input: &mut impl Read) -> Result<usize> {
        let header = Header::from_binary(input)?;
        ensure!(header.is_valid(), "Invalid Yaz0 magic");
        Ok(header.decompressed_size as usize)
    }
}

/// Decompresses the data into a new allocated [`Vec`]. Assumes a Yaz0 header followed by
/// compressed data.
pub fn decompress_file<D: Read + Seek>(input: &mut D) -> Result<Vec<u8>> {
    let decompressed_size = Header::decompressed_size(input)?;
    decompress(input, decompressed_size)
}

/// Decompresses the data into a new allocated [`Vec`]. `decompressed_size` can be determined
/// by looking at the Yaz0 header [`Header`].
pub fn decompress<D: Read + Seek>(input: &mut D, decompressed_size: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; decompressed_size];
    decompress_into(input, output.as_mut_slice())?;
    Ok(output)
}

/// Decompresses the data into the given buffer. The buffer must be large
/// enough to hold the decompressed data.
pub fn decompress_into<D: Read + Seek>(input: &mut D, destination: &mut [u8]) -> Result<()> {
    let decompressed_size = destination.len();
    let mut dest = 0;
    let mut code = 0;
    let mut code_bits = 0;

    while dest < decompressed_size {
        if code_bits == 0 {
            code = input.read_u8()? as u32;
            code_bits = 8;
        }

        if code & 0x80 != 0 {
            let byte = input.read_u8()?;
            destination[dest] = byte;
            dest += 1;
        } else {
            let byte0 = input.read_u8()?;
            let byte1 = input.read_u8()?;
            let a = (byte0 & 0xf) as usize;
            let b = (byte0 >> 4) as usize;
            let offset = (a << 8) | (byte1 as usize);
            let length = match b {
                0 => (input.read_u8()? as usize) + 0x12,
                length => length + 2,
            };

            ensure!(offset < dest, "Unexpected EOF");
            let base = dest - (offset + 1);
            for n in 0..length {
                destination[dest] = destination[base + n];
                dest += 1;
            }
        }

        code <<= 1;
        code_bits -= 1;
    }

    Ok(())
}
