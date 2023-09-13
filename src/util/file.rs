use std::{
    borrow::Cow,
    ffi::OsStr,
    fs::{DirBuilder, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use binrw::io::{TakeSeek, TakeSeekExt};
use byteorder::ReadBytesExt;
use filetime::{set_file_mtime, FileTime};
use memmap2::{Mmap, MmapOptions};
use path_slash::PathBufExt;
use sha1::{Digest, Sha1};

use crate::util::{rarc, rarc::Node, yaz0, IntoCow, ToCow};

pub struct MappedFile {
    mmap: Mmap,
    offset: u64,
    len: u64,
}

impl MappedFile {
    pub fn as_reader(&self) -> Cursor<&[u8]> { Cursor::new(self.as_slice()) }

    pub fn as_slice(&self) -> &[u8] {
        &self.mmap[self.offset as usize..self.offset as usize + self.len as usize]
    }

    pub fn len(&self) -> u64 { self.len }

    pub fn is_empty(&self) -> bool { self.len == 0 }

    pub fn into_inner(self) -> Mmap { self.mmap }
}

pub fn split_path<P: AsRef<Path>>(path: P) -> Result<(PathBuf, Option<PathBuf>)> {
    let mut base_path = PathBuf::new();
    let mut sub_path: Option<PathBuf> = None;
    for component in path.as_ref().components() {
        if let Component::Normal(str) = component {
            let str = str.to_str().ok_or(anyhow!("Path is not valid UTF-8"))?;
            if let Some((a, b)) = str.split_once(':') {
                base_path.push(a);
                sub_path = Some(PathBuf::from(b));
                continue;
            }
        }
        if let Some(sub_path) = &mut sub_path {
            sub_path.push(component);
        } else {
            base_path.push(component);
        }
    }
    Ok((base_path, sub_path))
}

/// Opens a memory mapped file, and decompresses it if needed.
pub fn map_file<P: AsRef<Path>>(path: P) -> Result<FileEntry> {
    let (base_path, sub_path) = split_path(path.as_ref())?;
    let file = File::open(&base_path)
        .with_context(|| format!("Failed to open file '{}'", base_path.display()))?;
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("Failed to mmap file: '{}'", base_path.display()))?;
    let (offset, len) = if let Some(sub_path) = sub_path {
        let mut reader = Cursor::new(&*mmap);
        if sub_path.as_os_str() == OsStr::new("nlzss") {
            return Ok(FileEntry::Buffer(nintendo_lz::decompress(&mut reader).map_err(|e| {
                anyhow!("Failed to decompress '{}' with NLZSS: {}", path.as_ref().display(), e)
            })?));
        } else if sub_path.as_os_str() == OsStr::new("yaz0") {
            return Ok(FileEntry::Buffer(yaz0::decompress_file(&mut reader).with_context(
                || format!("Failed to decompress '{}' with Yaz0", path.as_ref().display()),
            )?));
        }

        let rarc = rarc::RarcReader::new(&mut reader)
            .with_context(|| format!("Failed to open '{}' as RARC archive", base_path.display()))?;
        rarc.find_file(&sub_path)?.map(|(o, s)| (o, s as u64)).ok_or_else(|| {
            anyhow!("File '{}' not found in '{}'", sub_path.display(), base_path.display())
        })?
    } else {
        (0, mmap.len() as u64)
    };
    let map = MappedFile { mmap, offset, len };
    let buf = map.as_slice();
    // Auto-detect compression if there's a magic number.
    if buf.len() > 4 && buf[0..4] == *b"Yaz0" {
        return Ok(FileEntry::Buffer(yaz0::decompress_file(&mut map.as_reader()).with_context(
            || format!("Failed to decompress '{}' with Yaz0", path.as_ref().display()),
        )?));
    }
    Ok(FileEntry::MappedFile(map))
}

pub type OpenedFile = TakeSeek<File>;

/// Opens a file (not memory mapped). No decompression is performed.
pub fn open_file<P: AsRef<Path>>(path: P) -> Result<OpenedFile> {
    let (base_path, sub_path) = split_path(path)?;
    let mut file = File::open(&base_path)
        .with_context(|| format!("Failed to open file '{}'", base_path.display()))?;
    let (offset, size) = if let Some(sub_path) = sub_path {
        let rarc = rarc::RarcReader::new(&mut BufReader::new(&file))
            .with_context(|| format!("Failed to read RARC '{}'", base_path.display()))?;
        rarc.find_file(&sub_path)?.map(|(o, s)| (o, s as u64)).ok_or_else(|| {
            anyhow!("File '{}' not found in '{}'", sub_path.display(), base_path.display())
        })?
    } else {
        (0, file.seek(SeekFrom::End(0))?)
    };
    file.seek(SeekFrom::Start(offset))?;
    Ok(file.take_seek(size))
}

pub trait Reader: BufRead + Seek {}

impl Reader for Cursor<&[u8]> {}
// impl Reader for &mut OpenedFile {}

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
pub fn read_string<R: Read + Seek>(reader: &mut R, off: u64, size: usize) -> Result<String> {
    let mut data = vec![0u8; size];
    let pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(off))?;
    reader.read_exact(&mut data)?;
    reader.seek(SeekFrom::Start(pos))?;
    Ok(String::from_utf8(data)?)
}

/// Reads a zero-terminated string at the specified offset.
pub fn read_c_string<R: Read + Seek>(reader: &mut R, off: u64) -> Result<String> {
    let pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(off))?;
    let mut s = String::new();
    loop {
        let b = reader.read_u8()?;
        if b == 0 {
            break;
        }
        s.push(b as char);
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
    base_path: PathBuf,
    paths: Vec<(PathBuf, u64, u32)>,
    index: usize,
}

impl RarcIterator {
    pub fn new(file: Mmap, base_path: &Path) -> Result<Self> {
        let reader = rarc::RarcReader::new(&mut Cursor::new(&*file))?;
        let paths = Self::collect_paths(&reader, base_path);
        Ok(Self { file, base_path: base_path.to_owned(), paths, index: 0 })
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
    MappedFile(MappedFile),
    Buffer(Vec<u8>),
}

impl FileEntry {
    /// Creates a reader for the file.
    pub fn as_reader(&self) -> Box<dyn Reader + '_> {
        match self {
            Self::MappedFile(file) => Box::new(file.as_reader()),
            Self::Buffer(slice) => Box::new(Cursor::new(slice.as_slice())),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::MappedFile(file) => file.as_slice(),
            Self::Buffer(slice) => slice.as_slice(),
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::MappedFile(file) => file.len(),
            Self::Buffer(slice) => slice.len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::MappedFile(file) => file.is_empty(),
            Self::Buffer(slice) => slice.is_empty(),
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
                Some(Ok((path, buf))) => {
                    let mut path_str = rarc.base_path.as_os_str().to_os_string();
                    path_str.push(OsStr::new(":"));
                    path_str.push(path.as_os_str());
                    return Some(Ok((path, FileEntry::Buffer(buf))));
                }
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
            Ok(FileEntry::MappedFile(map)) => self.handle_file(map, path),
            Ok(FileEntry::Buffer(_)) => todo!(),
            Err(err) => Some(Err(err)),
        }
    }

    fn handle_file(
        &mut self,
        file: MappedFile,
        path: PathBuf,
    ) -> Option<Result<(PathBuf, FileEntry)>> {
        let buf = file.as_slice();
        if buf.len() <= 4 {
            return Some(Ok((path, FileEntry::MappedFile(file))));
        }

        match &buf[0..4] {
            b"Yaz0" => self.handle_yaz0(file.as_reader(), path),
            b"RARC" => self.handle_rarc(file.into_inner(), path),
            _ => Some(Ok((path, FileEntry::MappedFile(file)))),
        }
    }

    fn handle_yaz0(
        &mut self,
        mut reader: Cursor<&[u8]>,
        path: PathBuf,
    ) -> Option<Result<(PathBuf, FileEntry)>> {
        Some(match yaz0::decompress_file(&mut reader) {
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
        yaz0::decompress_file(&mut Cursor::new(buf))?.into_cow()
    } else {
        buf.to_cow()
    })
}

pub fn decompress_reader<R: Read + Seek>(reader: &mut R) -> Result<Vec<u8>> {
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() {
        reader.seek(SeekFrom::Start(0))?;
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        return Ok(buf);
    }
    Ok(if magic == *b"Yaz0" {
        reader.seek(SeekFrom::Start(0))?;
        yaz0::decompress_file(reader)?
    } else {
        let mut buf = magic.to_vec();
        reader.read_to_end(&mut buf)?;
        buf
    })
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
