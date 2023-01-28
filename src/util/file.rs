use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    path::Path,
};

use anyhow::{Context, Result};
use byteorder::ReadBytesExt;
use memmap2::{Mmap, MmapOptions};

/// Opens a memory mapped file.
pub fn map_file<P: AsRef<Path>>(path: P) -> Result<Mmap> {
    let file = File::open(&path)
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let map = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("Failed to mmap file: '{}'", path.as_ref().display()))?;
    Ok(map)
}

pub type Reader<'a> = Cursor<&'a [u8]>;

/// Creates a reader for the memory mapped file.
#[inline]
pub fn map_reader(mmap: &Mmap) -> Reader { Cursor::new(&*mmap) }

/// Creates a buffered reader around a file (not memory mapped).
pub fn buf_reader<P: AsRef<Path>>(path: P) -> Result<BufReader<File>> {
    let file = File::open(&path)
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    Ok(BufReader::new(file))
}

/// Reads a string with known size at the specified offset.
pub fn read_string(reader: &mut Reader, off: u64, size: usize) -> Result<String> {
    let mut data = vec![0u8; size];
    let pos = reader.position();
    reader.set_position(off);
    reader.read_exact(&mut data)?;
    reader.set_position(pos);
    Ok(String::from_utf8(data)?)
}

/// Reads a zero-terminated string at the specified offset.
pub fn read_c_string(reader: &mut Reader, off: u64) -> Result<String> {
    let pos = reader.position();
    reader.set_position(off);
    let mut s = String::new();
    loop {
        let b = reader.read_u8()?;
        if b == 0 {
            break;
        }
        s.push(b as char);
    }
    reader.set_position(pos);
    Ok(s)
}
