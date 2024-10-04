use std::{
    fs::{DirBuilder, File, OpenOptions},
    io,
    io::{BufRead, BufWriter, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use filetime::{set_file_mtime, FileTime};
use path_slash::PathBufExt;
use sha1::{Digest, Sha1};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    array_ref,
    util::{
        ncompress::{decompress_yay0, decompress_yaz0, YAY0_MAGIC, YAZ0_MAGIC},
        Bytes,
    },
    vfs::{open_path, VfsFile},
};

/// Creates a buffered writer around a file (not memory mapped).
pub fn buf_writer<P>(path: P) -> Result<BufWriter<File>>
where P: AsRef<Path> {
    if let Some(parent) = path.as_ref().parent() {
        DirBuilder::new().recursive(true).create(parent)?;
    }
    let file = File::create(&path)
        .with_context(|| format!("Failed to create file '{}'", path.as_ref().display()))?;
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
pub fn process_rsp(files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        if let Some(rsp_file) = path_str.strip_prefix('@') {
            let rsp_path = Path::new(rsp_file);
            let file = open_path(rsp_path, true)?;
            for result in file.lines() {
                let line = result?;
                if !line.is_empty() {
                    out.push(PathBuf::from_slash(line));
                }
            }
        } else if path_str.contains('*') {
            for entry in glob::glob(path_str)? {
                out.push(entry?);
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
    paths: Vec<PathBuf>,
    index: usize,
}

impl FileIterator {
    pub fn new(paths: &[PathBuf]) -> Result<Self> {
        Ok(Self { paths: process_rsp(paths)?, index: 0 })
    }

    fn next_path(&mut self) -> Option<Result<(PathBuf, Box<dyn VfsFile>)>> {
        if self.index >= self.paths.len() {
            return None;
        }

        let path = self.paths[self.index].clone();
        self.index += 1;
        match open_path(&path, true) {
            Ok(file) => Some(Ok((path, file))),
            Err(e) => Some(Err(e)),
        }
    }
}

impl Iterator for FileIterator {
    type Item = Result<(PathBuf, Box<dyn VfsFile>)>;

    fn next(&mut self) -> Option<Self::Item> { self.next_path() }
}

pub fn touch<P>(path: P) -> io::Result<()>
where P: AsRef<Path> {
    if path.as_ref().exists() {
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
    let mut expected_bytes = [0u8; 20];
    hex::decode_to_slice(expected_str, &mut expected_bytes)
        .with_context(|| format!("Invalid SHA-1 '{expected_str}'"))?;
    let mut hasher = Sha1::new();
    hasher.update(buf);
    let hash_bytes = hasher.finalize();
    if hash_bytes.as_ref() == expected_bytes {
        Ok(())
    } else {
        Err(anyhow!(
            "Hash mismatch: expected {}, but was {}",
            hex::encode(expected_bytes),
            hex::encode(hash_bytes)
        ))
    }
}
