use std::{
    fs,
    fs::{DirBuilder, File, OpenOptions},
    io,
    io::{BufRead, BufWriter, Read, Seek, SeekFrom, Write},
};

use anyhow::{anyhow, Context, Result};
use filetime::{set_file_mtime, FileTime};
use sha1::{Digest, Sha1};
use typed_path::{Utf8NativePath, Utf8NativePathBuf, Utf8UnixPathBuf};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    array_ref,
    util::{
        ncompress::{decompress_yay0, decompress_yaz0, YAY0_MAGIC, YAZ0_MAGIC},
        path::check_path_buf,
        Bytes,
    },
    vfs::{open_file, VfsFile},
};

/// Creates a buffered writer around a file (not memory mapped).
pub fn buf_writer(path: &Utf8NativePath) -> Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        DirBuilder::new().recursive(true).create(parent)?;
    }
    let file = File::create(path).with_context(|| format!("Failed to create file '{path}'"))?;
    Ok(BufWriter::new(file))
}

/// Reads a string with known size at the specified offset.
pub fn read_string<R>(reader: &mut R, off: u64, size: usize) -> io::Result<String>
where R: Read + Seek + ?Sized {
    let mut data = vec![0u8; size];
    let pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(off))?;
    reader.read_exact(&mut data)?;
    reader.seek(SeekFrom::Start(pos))?;
    String::from_utf8(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads a zero-terminated string at the specified offset.
pub fn read_c_string<R>(reader: &mut R, off: u64) -> io::Result<String>
where R: Read + Seek + ?Sized {
    let pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(off))?;
    let mut s = String::new();
    let mut buf = [0u8; 1];
    loop {
        reader.read_exact(&mut buf)?;
        if buf[0] == 0 {
            break;
        }
        s.push(buf[0] as char);
    }
    reader.seek(SeekFrom::Start(pos))?;
    Ok(s)
}

/// Process response files (starting with '@') and glob patterns (*).
pub fn process_rsp(files: &[Utf8NativePathBuf]) -> Result<Vec<Utf8NativePathBuf>> {
    let mut out = Vec::<Utf8NativePathBuf>::with_capacity(files.len());
    for path in files {
        if let Some(rsp_file) = path.as_str().strip_prefix('@') {
            let file = open_file(Utf8NativePath::new(rsp_file), true)?;
            for result in file.lines() {
                let line = result?;
                if !line.is_empty() {
                    out.push(Utf8UnixPathBuf::from(line).with_encoding());
                }
            }
        } else if path.as_str().contains('*') {
            for entry in glob::glob(path.as_str())? {
                let path = check_path_buf(entry?)?;
                out.push(path.with_encoding());
            }
        } else {
            out.push(path.clone());
        }
    }
    Ok(out)
}

/// Information about a file when it was read.
/// Used to determine if a file has changed since it was read (mtime)
/// and if it needs to be written (hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReadInfo {
    pub mtime: Option<FileTime>,
    pub hash: u64,
}

impl FileReadInfo {
    pub fn new(entry: &mut dyn VfsFile) -> Result<Self> {
        let hash = xxh3_64(entry.map()?);
        let metadata = entry.metadata()?;
        Ok(Self { mtime: metadata.mtime, hash })
    }
}

/// Iterate over file paths, expanding response files (@) and glob patterns (*).
/// If a file is a RARC archive, iterate over its contents.
/// If a file is a Yaz0 compressed file, decompress it.
pub struct FileIterator {
    paths: Vec<Utf8NativePathBuf>,
    index: usize,
}

impl FileIterator {
    pub fn new(paths: &[Utf8NativePathBuf]) -> Result<Self> {
        Ok(Self { paths: process_rsp(paths)?, index: 0 })
    }

    fn next_path(&mut self) -> Option<Result<(Utf8NativePathBuf, Box<dyn VfsFile>)>> {
        if self.index >= self.paths.len() {
            return None;
        }

        let path = self.paths[self.index].clone();
        self.index += 1;
        match open_file(&path, true) {
            Ok(file) => Some(Ok((path, file))),
            Err(e) => Some(Err(e)),
        }
    }
}

impl Iterator for FileIterator {
    type Item = Result<(Utf8NativePathBuf, Box<dyn VfsFile>)>;

    fn next(&mut self) -> Option<Self::Item> { self.next_path() }
}

pub fn touch(path: &Utf8NativePath) -> io::Result<()> {
    if fs::exists(path)? {
        set_file_mtime(path, FileTime::now())
    } else {
        match OpenOptions::new().create(true).truncate(true).write(true).open(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn decompress_if_needed(buf: &[u8]) -> Result<Bytes> {
    if buf.len() > 4 {
        match *array_ref!(buf, 0, 4) {
            YAZ0_MAGIC => return decompress_yaz0(buf).map(Bytes::Owned),
            YAY0_MAGIC => return decompress_yay0(buf).map(Bytes::Owned),
            _ => {}
        }
    }
    Ok(Bytes::Borrowed(buf))
}

pub fn verify_hash(buf: &[u8], expected_str: &str) -> Result<()> {
    let mut hasher = Sha1::new();
    hasher.update(buf);
    check_hash_str(hasher.finalize().into(), expected_str)
}

pub fn check_hash_str(hash_bytes: [u8; 20], expected_str: &str) -> Result<()> {
    let mut expected_bytes = [0u8; 20];
    hex::decode_to_slice(expected_str, &mut expected_bytes)
        .with_context(|| format!("Invalid SHA-1 '{expected_str}'"))?;
    if hash_bytes == expected_bytes {
        Ok(())
    } else {
        Err(anyhow!(
            "Hash mismatch: expected {}, but was {}",
            hex::encode(expected_bytes),
            hex::encode(hash_bytes)
        ))
    }
}

/// Copies from a buffered reader to a writer without extra allocations.
pub fn buf_copy<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: BufRead + ?Sized,
    W: Write + ?Sized,
{
    let mut copied = 0;
    loop {
        let buf = reader.fill_buf()?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        writer.write_all(buf)?;
        reader.consume(len);
        copied += len as u64;
    }
    Ok(copied)
}

/// Copies from a buffered reader to a writer without extra allocations.
/// Generates an SHA-1 hash of the data as it is copied.
pub fn buf_copy_with_hash<R, W>(reader: &mut R, writer: &mut W) -> io::Result<[u8; 20]>
where
    R: BufRead + ?Sized,
    W: Write + ?Sized,
{
    let mut hasher = Sha1::new();
    loop {
        let buf = reader.fill_buf()?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        hasher.update(buf);
        writer.write_all(buf)?;
        reader.consume(len);
    }
    Ok(hasher.finalize().into())
}
