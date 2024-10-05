// BSD 2-Clause License
//
// Copyright (c) 2018, Charlotte D
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Source: https://gitlab.com/DarkKirb/nintendo-lz
// Modified to compile with latest edition, use anyhow::Error, and fix various issues.

use std::io::{Cursor, Read, Write};

use anyhow::{bail, ensure, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Decompresses an LZ10/LZ11 compressed file. It returns an error when:
///
/// - The file is not a valid LZ10/LZ11 file
/// - The file is truncated (More data was expected than present)
///
/// # Example
///
/// ```rust,ignore
/// let mut f = File::open("Archive.bin.cmp");
/// let mut decompressed = nintendo_lz::decompress(&mut f).unwrap();
/// ```
pub fn decompress<R>(inp: &mut R) -> Result<Vec<u8>>
where R: Read + ?Sized {
    let mut length = inp.read_u32::<LittleEndian>()? as usize;
    let ver = match length & 0xFF {
        0x10 => 0,
        0x11 => 1,
        _ => bail!("Invalid magic number"),
    };
    length >>= 8;
    if length == 0 && ver == 1 {
        length = inp.read_u32::<LittleEndian>()? as usize;
    }
    let mut out = Vec::<u8>::with_capacity(length);
    while out.len() < length {
        let byte = inp.read_u8()?;
        for bit_no in (0..8).rev() {
            if out.len() >= length {
                break;
            }
            if ((byte >> bit_no) & 1) == 0 {
                let data = inp.read_u8()?;
                out.push(data);
            } else {
                let lenmsb = inp.read_u8()? as usize;
                let lsb = inp.read_u8()? as usize;
                let mut length: usize = lenmsb >> 4;
                let mut disp: usize = ((lenmsb & 15) << 8) + lsb;
                if ver == 0 {
                    length += 3;
                } else if length > 1 {
                    length += 1;
                } else if length == 0 {
                    length = (lenmsb & 15) << 4;
                    length += lsb >> 4;
                    length += 0x11;
                    let msb = inp.read_u8()? as usize;
                    disp = ((lsb & 15) << 8) + msb;
                } else {
                    length = (lenmsb & 15) << 12;
                    length += lsb << 4;
                    let byte1 = inp.read_u8()? as usize;
                    let byte2 = inp.read_u8()? as usize;
                    length += byte1 >> 4;
                    length += 0x111;
                    disp = ((byte1 & 15) << 8) + byte2;
                }
                let start: usize = out.len() - disp - 1;

                for i in 0..length {
                    let val = out[start + i];
                    out.push(val);
                }
            }
        }
    }
    Ok(out)
}

/// This function is a convenience wrapper around `decompress` for decompressing slices, arrays or
/// vectors.
pub fn decompress_arr(input: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(input);
    decompress(&mut reader)
}

/// This enum contains the possible compression levels for LZ compression.
pub enum CompressionLevel {
    /// LZ10 compression. Maximum repeat size: 18 bytes
    LZ10,
    /// LZ11 compression. Maximum repeat size: 65809 bytes
    ///
    /// Argument: Maximum repeat size (0..65810), lower means worse compression but higher speed.
    /// for values < 3 compression is disabled
    LZ11(u32),
}

fn find_longest_match(data: &[u8], off: usize, max: usize) -> Option<(usize, usize)> {
    if off < 4 || data.len() - off < 4 {
        return None;
    }
    let mut longest_pos: usize = 0;
    let mut longest_len: usize = 0;
    let mut start = 0;
    if off > 0x1000 {
        start = off - 0x1000;
    }
    for pos in search(&data[start..off + 2], &data[off..off + 3]) {
        let mut length = 0;
        for (i, p) in (off..data.len()).enumerate() {
            if length == max {
                return Some((start + pos, length));
            }
            if data[p] != data[start + pos + i] {
                break;
            }
            length += 1;
        }
        if length > longest_len {
            longest_pos = pos;
            longest_len = length;
        }
    }
    if longest_len < 3 {
        return None;
    }
    Some((start + longest_pos, longest_len))
}

/// Compresses data to LZ10/LZ11. It returns an error when:
///
/// - The input is too large for the selected LZ version (LZ10 supports at most 16MiB)
/// - The maximum repeat length is out of range (for LZ11, has to be in the range (0..65810)
/// - Writing to the output file failed
///
/// # Example
///
/// ```rust,ignore
/// let mut f = File::create("Archive.bin.cmp");
/// let data = b"This is an example text. This is an example text";
/// nintendo_lz::compress(&data, &mut f, nintendo_lz::CompressionLevel::LZ11(65809)).unwrap();
/// ```
pub fn compress<W>(inp: &[u8], out: &mut W, level: CompressionLevel) -> Result<()>
where W: Write + ?Sized {
    let ver = match level {
        CompressionLevel::LZ10 => 0,
        CompressionLevel::LZ11(_) => 1,
    };
    if ver == 0 && inp.len() > 16777216 {
        bail!("Input data too large for LZ10");
    }
    if ver == 1 && inp.len() as u64 > 0xFFFFFFFF {
        bail!("Input data too large for LZ11");
    }
    let repeat_size = match level {
        CompressionLevel::LZ10 => 18,
        CompressionLevel::LZ11(max) => max,
    };
    ensure!(repeat_size < 65810, "Maximum repeat size out of range. (0..65810)");

    let size: usize = inp.len();

    if size < 16777216 && (size != 0 || ver == 0) {
        let header = 0x10 + ver + ((size as u32) << 8);
        out.write_u32::<LittleEndian>(header)?;
    } else {
        out.write_u32::<LittleEndian>(0x11)?;
        out.write_u32::<LittleEndian>(size as u32)?;
    }

    let mut off: usize = 0;
    let mut byte: u8 = 0;
    let mut index = 7;
    let mut cmpbuf: Vec<u8> = Vec::new();

    while off < size {
        match find_longest_match(inp, off, repeat_size as usize) {
            None => {
                index -= 1;
                cmpbuf.push(inp[off]);
                off += 1;
            }
            Some((pos, len)) => {
                let lz_off: usize = off - pos - 1;
                byte |= 1 << index;
                index -= 1;
                if ver == 0 {
                    let l = len - 3;
                    let cmp: [u8; 2] = [((lz_off >> 8) as u8) + ((l << 4) as u8), lz_off as u8];
                    cmpbuf.extend_from_slice(&cmp);
                } else if len < 0x11 {
                    let l = len - 1;
                    let cmp: [u8; 2] = [((lz_off >> 8) as u8) + ((l << 4) as u8), lz_off as u8];
                    cmpbuf.extend_from_slice(&cmp);
                } else if len < 0x111 {
                    let l = len - 0x11;
                    let cmp: [u8; 3] =
                        [(l >> 4) as u8, ((lz_off >> 8) as u8) + ((l << 4) as u8), lz_off as u8];
                    cmpbuf.extend_from_slice(&cmp);
                } else {
                    let l = len - 0x111;
                    let cmp: [u8; 4] = [
                        (l >> 12) as u8 + 0x10,
                        (l >> 4) as u8,
                        ((lz_off >> 8) as u8) + ((l << 4) as u8),
                        lz_off as u8,
                    ];
                    cmpbuf.extend_from_slice(&cmp);
                }
                off += len;
            }
        };
        if index < 0 {
            out.write_u8(byte)?;
            out.write_all(&cmpbuf)?;
            byte = 0;
            index = 7;
            cmpbuf.clear();
        }
    }
    if !cmpbuf.is_empty() {
        out.write_u8(byte)?;
        out.write_all(&cmpbuf)?;
    }
    out.write_u8(0xFF)?;

    Ok(())
}

/// This function is a convenience wrapper around `compress` for compressing to a Vec<u8>.
/// Additionally, it uses LZ11 as compression algorithm by default.
pub fn compress_arr(input: &[u8]) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    {
        let mut writer = Cursor::new(&mut out);
        compress(input, &mut writer, CompressionLevel::LZ11(65809))?;
    }
    Ok(out)
}

fn get_needle_table(needle: &[u8]) -> [usize; 256] {
    let mut needle_table = [needle.len(); 256];
    for (i, c) in needle.iter().enumerate() {
        needle_table[*c as usize] = needle.len() - i;
    }
    needle_table
}

pub fn search_one(haystack: &[u8], needle: &[u8], needle_table: &[usize; 256]) -> Option<usize> {
    let mut cur = 0;
    while haystack.len() - cur >= needle.len() {
        let mut output = None;
        for i in (0..needle.len()).rev() {
            if haystack[cur + i] == needle[i] {
                output = Some(cur);
                break;
            }
        }
        if output.is_some() {
            return output;
        }
        cur += needle_table[haystack[cur + needle.len() - 1] as usize];
    }
    None
}

fn search(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let needle_table = get_needle_table(needle);
    let mut cur = 0usize;
    let mut positions = Vec::new();
    while cur + needle.len() < haystack.len() {
        let found_pos = search_one(&haystack[cur..], needle, &needle_table);
        if let Some(pos) = found_pos {
            positions.push(pos);
            cur += pos + needle.len() + 1;
        } else {
            return positions;
        }
    }
    positions
}
