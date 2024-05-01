use anyhow::{anyhow, Result};
use orthrus_ncompress::{yay0::Yay0, yaz0::Yaz0};

pub const YAZ0_MAGIC: [u8; 4] = *b"Yaz0";
pub const YAY0_MAGIC: [u8; 4] = *b"Yay0";

/// Compresses the data into a new allocated buffer using Yaz0 compression.
pub fn compress_yaz0(input: &[u8]) -> Box<[u8]> {
    let mut output = vec![0u8; Yaz0::worst_possible_size(input.len())];
    let size = Yaz0::compress_n64(input, output.as_mut_slice());
    output.truncate(size);
    output.into_boxed_slice()
}

/// Decompresses the data into a new allocated buffer. Assumes a Yaz0 header followed by
/// compressed data.
pub fn decompress_yaz0(input: &[u8]) -> Result<Box<[u8]>> {
    Yaz0::decompress_from(input).map_err(|e| anyhow!(e))
}

/// Compresses the data into a new allocated buffer using Yay0 compression.
pub fn compress_yay0(input: &[u8]) -> Box<[u8]> {
    let mut output = vec![0u8; Yay0::worst_possible_size(input.len())];
    let size = Yay0::compress_n64(input, output.as_mut_slice());
    output.truncate(size);
    output.into_boxed_slice()
}

/// Decompresses the data into a new allocated buffer. Assumes a Yay0 header followed by
/// compressed data.
pub fn decompress_yay0(input: &[u8]) -> Result<Box<[u8]>> {
    Yay0::decompress_from(input).map_err(|e| anyhow!(e))
}
