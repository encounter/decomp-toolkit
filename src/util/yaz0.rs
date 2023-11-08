// Source: https://github.com/Julgodis/picori/blob/650da9f4fe6050b39b80d5360416591c748058d5/src/yaz0.rs
// License: MIT
// Modified to use `std::io::Read`/`Seek` and project's FromReader trait.
use std::io::{Read, Seek};

use anyhow::{ensure, Result};

use crate::util::reader::{skip_bytes, struct_size, Endian, FromReader};

pub const YAZ0_MAGIC: [u8; 4] = *b"Yaz0";

/// Yaz0 header.
pub struct Header {
    /// Size of decompressed data.
    pub decompressed_size: u32,
}

impl FromReader for Header {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // magic
        u32::STATIC_SIZE, // decompressed_size
        u32::STATIC_SIZE, // reserved0
        u32::STATIC_SIZE, // reserved1
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> std::io::Result<Self>
    where R: Read + Seek + ?Sized {
        let magic = <[u8; 4]>::from_reader(reader, e)?;
        if magic != YAZ0_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Yaz0 magic: {:?}", magic),
            ));
        }
        let decompressed_size = u32::from_reader(reader, e)?;
        skip_bytes::<8, _>(reader)?;
        Ok(Self { decompressed_size })
    }
}

/// Decompresses the data into a new allocated [`Vec`]. Assumes a Yaz0 header followed by
/// compressed data.
pub fn decompress_file<R>(input: &mut R) -> Result<Vec<u8>>
where R: Read + Seek + ?Sized {
    let header = Header::from_reader(input, Endian::Big)?;
    decompress(input, header.decompressed_size as usize)
}

/// Decompresses the data into a new allocated [`Vec`]. `decompressed_size` can be determined
/// by looking at the Yaz0 header [`Header`].
pub fn decompress<R>(input: &mut R, decompressed_size: usize) -> Result<Vec<u8>>
where R: Read + Seek + ?Sized {
    let mut output = vec![0; decompressed_size];
    decompress_into(input, output.as_mut_slice())?;
    Ok(output)
}

/// Decompresses the data into the given buffer. The buffer must be large
/// enough to hold the decompressed data.
pub fn decompress_into<R>(input: &mut R, destination: &mut [u8]) -> Result<()>
where R: Read + Seek + ?Sized {
    let decompressed_size = destination.len();
    let mut dest = 0;
    let mut code = 0;
    let mut code_bits = 0;

    while dest < decompressed_size {
        if code_bits == 0 {
            code = u8::from_reader(input, Endian::Big)? as u32;
            code_bits = 8;
        }

        if code & 0x80 != 0 {
            destination[dest] = u8::from_reader(input, Endian::Big)?;
            dest += 1;
        } else {
            let bytes = <[u8; 2]>::from_reader(input, Endian::Big)?;
            let a = (bytes[0] & 0xf) as usize;
            let b = (bytes[0] >> 4) as usize;
            let offset = (a << 8) | (bytes[1] as usize);
            let length = match b {
                0 => (u8::from_reader(input, Endian::Big)? as usize) + 0x12,
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
