use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    path::Path, ops::Index,
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

///SOURCE: https://referencesource.microsoft.com/#mscorlib/system/io/path.cs,88
static INVALID_FILE_NAME_CHARS: &'static [char] = &['"', '<', '>', '|', '\0', 1 as char, 2 as char, 3 as char, 4 as char, 5 as char, 6 as char, 7 as char, 8 as char, 9 as char, 10 as char, 11 as char, 12 as char, 13 as char, 14 as char, 15 as char, 16 as char, 17 as char, 18 as char, 19 as char, 20 as char, 21 as char, 22 as char, 23 as char, 24 as char, 25 as char, 26 as char, 27 as char, 28 as char, 29 as char, 30 as char, 31 as char, ':', '*', '?', '\\', '/'];

/// Sanitize string for to be file name compatible
pub fn sanitize_str_for_filename(value: &str) -> String {
    let mut retval = String::with_capacity(value.len());

    for ch in value.chars() {
        if let Some(_) = INVALID_FILE_NAME_CHARS.iter().position(|c| *c == ch) {
            continue;
        }
        retval.push(ch)
    }

    retval
}
