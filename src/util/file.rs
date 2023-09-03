use std::{
    borrow::Cow,
    fs::{DirBuilder, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Cursor, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use byteorder::ReadBytesExt;
use filetime::{set_file_mtime, FileTime};
use memmap2::{Mmap, MmapOptions};
use path_slash::PathBufExt;

use crate::{
    cmd::shasum::file_sha1,
    util::{rarc, rarc::Node, yaz0, IntoCow, ToCow},
};

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
pub fn map_reader(mmap: &Mmap) -> Reader { Reader::new(&**mmap) }

/// Creates a buffered reader around a file (not memory mapped).
pub fn buf_reader<P: AsRef<Path>>(path: P) -> Result<BufReader<File>> {
    let file = File::open(&path)
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    Ok(BufReader::new(file))
}

/// Creates a buffered writer around a file (not memory mapped).
pub fn buf_writer<P: AsRef<Path>>(path: P) -> Result<BufWriter<File>> {
    if let Some(parent) = path.as_ref().parent() {
        DirBuilder::new().recursive(true).create(parent)?;
    }
    let file = File::create(&path)
        .with_context(|| format!("Failed to create file '{}'", path.as_ref().display()))?;
    Ok(BufWriter::new(file))
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

/// Process response files (starting with '@') and glob patterns (*).
pub fn process_rsp(files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        if let Some(rsp_file) = path_str.strip_prefix('@') {
            let reader = buf_reader(rsp_file)?;
            for result in reader.lines() {
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

/// Iterator over files in a RARC archive.
struct RarcIterator {
    file: Mmap,
    paths: Vec<(PathBuf, u64, u32)>,
    index: usize,
}

impl RarcIterator {
    pub fn new(file: Mmap, base_path: &Path) -> Result<Self> {
        let reader = rarc::RarcReader::new(map_reader(&file))?;
        let paths = Self::collect_paths(&reader, base_path);
        Ok(Self { file, paths, index: 0 })
    }

    fn collect_paths(reader: &rarc::RarcReader, base_path: &Path) -> Vec<(PathBuf, u64, u32)> {
        let mut current_path = PathBuf::new();
        let mut paths = vec![];
        for node in reader.nodes() {
            match node {
                Node::DirectoryBegin { name } => {
                    current_path.push(name.name);
                }
                Node::DirectoryEnd { name: _ } => {
                    current_path.pop();
                }
                Node::File { name, offset, size } => {
                    let path = base_path.join(&current_path).join(name.name);
                    paths.push((path, offset, size));
                }
                Node::CurrentDirectory => {}
                Node::ParentDirectory => {}
            }
        }
        paths
    }
}

impl Iterator for RarcIterator {
    type Item = Result<(PathBuf, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.paths.len() {
            return None;
        }

        let (path, off, size) = self.paths[self.index].clone();
        self.index += 1;

        let slice = &self.file[off as usize..off as usize + size as usize];
        match decompress_if_needed(slice) {
            Ok(buf) => Some(Ok((path, buf.into_owned()))),
            Err(e) => Some(Err(e)),
        }
    }
}

/// A file entry, either a memory mapped file or an owned buffer.
pub enum FileEntry {
    Map(Mmap),
    Buffer(Vec<u8>),
}

impl FileEntry {
    /// Creates a reader for the file.
    pub fn as_reader(&self) -> Reader {
        match self {
            Self::Map(map) => map_reader(map),
            Self::Buffer(slice) => Reader::new(slice),
        }
    }
}

/// Iterate over file paths, expanding response files (@) and glob patterns (*).
/// If a file is a RARC archive, iterate over its contents.
/// If a file is a Yaz0 compressed file, decompress it.
pub struct FileIterator {
    paths: Vec<PathBuf>,
    index: usize,
    rarc: Option<RarcIterator>,
}

impl FileIterator {
    pub fn new(paths: &[PathBuf]) -> Result<Self> {
        Ok(Self { paths: process_rsp(paths)?, index: 0, rarc: None })
    }

    fn next_rarc(&mut self) -> Option<Result<(PathBuf, FileEntry)>> {
        if let Some(rarc) = &mut self.rarc {
            match rarc.next() {
                Some(Ok((path, buf))) => return Some(Ok((path, FileEntry::Buffer(buf)))),
                Some(Err(err)) => return Some(Err(err)),
                None => self.rarc = None,
            }
        }
        None
    }

    fn next_path(&mut self) -> Option<Result<(PathBuf, FileEntry)>> {
        if self.index >= self.paths.len() {
            return None;
        }

        let path = self.paths[self.index].clone();
        self.index += 1;
        match map_file(&path) {
            Ok(map) => self.handle_file(map, path),
            Err(err) => Some(Err(err)),
        }
    }

    fn handle_file(&mut self, map: Mmap, path: PathBuf) -> Option<Result<(PathBuf, FileEntry)>> {
        if map.len() <= 4 {
            return Some(Ok((path, FileEntry::Map(map))));
        }

        match &map[0..4] {
            b"Yaz0" => self.handle_yaz0(map, path),
            b"RARC" => self.handle_rarc(map, path),
            _ => Some(Ok((path, FileEntry::Map(map)))),
        }
    }

    fn handle_yaz0(&mut self, map: Mmap, path: PathBuf) -> Option<Result<(PathBuf, FileEntry)>> {
        Some(match yaz0::decompress_file(&mut map_reader(&map)) {
            Ok(buf) => Ok((path, FileEntry::Buffer(buf))),
            Err(e) => Err(e),
        })
    }

    fn handle_rarc(&mut self, map: Mmap, path: PathBuf) -> Option<Result<(PathBuf, FileEntry)>> {
        self.rarc = match RarcIterator::new(map, &path) {
            Ok(iter) => Some(iter),
            Err(e) => return Some(Err(e)),
        };
        self.next()
    }
}

impl Iterator for FileIterator {
    type Item = Result<(PathBuf, FileEntry)>;

    fn next(&mut self) -> Option<Self::Item> { self.next_rarc().or_else(|| self.next_path()) }
}

pub fn touch<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    if path.as_ref().exists() {
        set_file_mtime(path, FileTime::now())
    } else {
        match OpenOptions::new().create(true).write(true).open(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn decompress_if_needed(buf: &[u8]) -> Result<Cow<[u8]>> {
    Ok(if buf.len() > 4 && buf[0..4] == *b"Yaz0" {
        yaz0::decompress_file(&mut Reader::new(buf))?.into_cow()
    } else {
        buf.to_cow()
    })
}

pub fn verify_hash<P: AsRef<Path>>(path: P, hash_str: &str) -> Result<()> {
    let mut hash_bytes = [0u8; 20];
    hex::decode_to_slice(hash_str, &mut hash_bytes)
        .with_context(|| format!("Invalid SHA-1 '{hash_str}'"))?;
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let found_hash = file_sha1(file)?;
    if found_hash.as_ref() == hash_bytes {
        Ok(())
    } else {
        Err(anyhow!(
            "Hash mismatch: expected {}, but was {}",
            hex::encode(hash_bytes),
            hex::encode(found_hash)
        ))
    }
}
