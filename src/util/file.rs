use std::{
    ffi::OsStr,
    fs::{DirBuilder, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use filetime::{set_file_mtime, FileTime};
use memmap2::{Mmap, MmapOptions};
use path_slash::PathBufExt;
use rarc::RarcReader;
use sha1::{Digest, Sha1};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    array_ref,
    util::{
        ncompress::{decompress_yay0, decompress_yaz0, YAY0_MAGIC, YAZ0_MAGIC},
        rarc,
        rarc::{Node, RARC_MAGIC},
        take_seek::{TakeSeek, TakeSeekExt},
        u8_arc::{U8View, U8_MAGIC},
        Bytes,
    },
};

pub struct MappedFile {
    mmap: Mmap,
    mtime: FileTime,
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

pub fn split_path<P>(path: P) -> Result<(PathBuf, Option<PathBuf>)>
where P: AsRef<Path> {
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
pub fn map_file<P>(path: P) -> Result<FileEntry>
where P: AsRef<Path> {
    let (base_path, sub_path) = split_path(path.as_ref())?;
    let file = File::open(&base_path)
        .with_context(|| format!("Failed to open file '{}'", base_path.display()))?;
    let mtime = FileTime::from_last_modification_time(&file.metadata()?);
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("Failed to mmap file: '{}'", base_path.display()))?;
    let (offset, len) = if let Some(sub_path) = sub_path {
        if sub_path.as_os_str() == OsStr::new("nlzss") {
            return Ok(FileEntry::Buffer(
                nintendo_lz::decompress(&mut mmap.as_ref())
                    .map_err(|e| {
                        anyhow!(
                            "Failed to decompress '{}' with NLZSS: {}",
                            path.as_ref().display(),
                            e
                        )
                    })?
                    .into_boxed_slice(),
                mtime,
            ));
        } else if sub_path.as_os_str() == OsStr::new("yaz0") {
            return Ok(FileEntry::Buffer(
                decompress_yaz0(mmap.as_ref()).with_context(|| {
                    format!("Failed to decompress '{}' with Yaz0", path.as_ref().display())
                })?,
                mtime,
            ));
        } else if sub_path.as_os_str() == OsStr::new("yay0") {
            return Ok(FileEntry::Buffer(
                decompress_yay0(mmap.as_ref()).with_context(|| {
                    format!("Failed to decompress '{}' with Yay0", path.as_ref().display())
                })?,
                mtime,
            ));
        }

        let buf = mmap.as_ref();
        match *array_ref!(buf, 0, 4) {
            RARC_MAGIC => {
                let rarc = RarcReader::new(&mut Cursor::new(mmap.as_ref())).with_context(|| {
                    format!("Failed to open '{}' as RARC archive", base_path.display())
                })?;
                let (offset, size) = rarc.find_file(&sub_path)?.ok_or_else(|| {
                    anyhow!("File '{}' not found in '{}'", sub_path.display(), base_path.display())
                })?;
                (offset, size as u64)
            }
            U8_MAGIC => {
                let arc = U8View::new(buf).map_err(|e| {
                    anyhow!("Failed to open '{}' as U8 archive: {}", base_path.display(), e)
                })?;
                let (_, node) = arc.find(sub_path.to_slash_lossy().as_ref()).ok_or_else(|| {
                    anyhow!("File '{}' not found in '{}'", sub_path.display(), base_path.display())
                })?;
                (node.offset() as u64, node.length() as u64)
            }
            _ => bail!("Couldn't detect archive type for '{}'", path.as_ref().display()),
        }
    } else {
        (0, mmap.len() as u64)
    };
    let map = MappedFile { mmap, mtime, offset, len };
    let buf = map.as_slice();
    // Auto-detect compression if there's a magic number.
    if buf.len() > 4 {
        match *array_ref!(buf, 0, 4) {
            YAZ0_MAGIC => {
                return Ok(FileEntry::Buffer(
                    decompress_yaz0(buf).with_context(|| {
                        format!("Failed to decompress '{}' with Yaz0", path.as_ref().display())
                    })?,
                    mtime,
                ));
            }
            YAY0_MAGIC => {
                return Ok(FileEntry::Buffer(
                    decompress_yay0(buf).with_context(|| {
                        format!("Failed to decompress '{}' with Yay0", path.as_ref().display())
                    })?,
                    mtime,
                ));
            }
            _ => {}
        }
    }
    Ok(FileEntry::MappedFile(map))
}

/// Opens a memory mapped file without decompression or archive handling.
pub fn map_file_basic<P>(path: P) -> Result<FileEntry>
where P: AsRef<Path> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("Failed to open file '{}'", path.display()))?;
    let mtime = FileTime::from_last_modification_time(&file.metadata()?);
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("Failed to mmap file: '{}'", path.display()))?;
    let len = mmap.len() as u64;
    Ok(FileEntry::MappedFile(MappedFile { mmap, mtime, offset: 0, len }))
}

pub type OpenedFile = TakeSeek<File>;

/// Opens a file (not memory mapped). No decompression is performed.
pub fn open_file<P>(path: P) -> Result<OpenedFile>
where P: AsRef<Path> {
    let (base_path, sub_path) = split_path(path)?;
    let mut file = File::open(&base_path)
        .with_context(|| format!("Failed to open file '{}'", base_path.display()))?;
    let (offset, size) = if let Some(sub_path) = sub_path {
        let rarc = RarcReader::new(&mut BufReader::new(&file))
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

/// Creates a buffered reader around a file (not memory mapped).
pub fn buf_reader<P>(path: P) -> Result<BufReader<File>>
where P: AsRef<Path> {
    let file = File::open(&path)
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    Ok(BufReader::new(file))
}

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
pub fn read_string<R>(reader: &mut R, off: u64, size: usize) -> Result<String>
where R: Read + Seek + ?Sized {
    let mut data = vec![0u8; size];
    let pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(off))?;
    reader.read_exact(&mut data)?;
    reader.seek(SeekFrom::Start(pos))?;
    Ok(String::from_utf8(data)?)
}

/// Reads a zero-terminated string at the specified offset.
pub fn read_c_string<R>(reader: &mut R, off: u64) -> Result<String>
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
    file: MappedFile,
    base_path: PathBuf,
    paths: Vec<(PathBuf, u64, u32)>,
    index: usize,
}

impl RarcIterator {
    pub fn new(file: MappedFile, base_path: &Path) -> Result<Self> {
        let reader = RarcReader::new(&mut file.as_reader())?;
        let paths = Self::collect_paths(&reader, base_path);
        Ok(Self { file, base_path: base_path.to_owned(), paths, index: 0 })
    }

    fn collect_paths(reader: &RarcReader, base_path: &Path) -> Vec<(PathBuf, u64, u32)> {
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
    type Item = Result<(PathBuf, Box<[u8]>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.paths.len() {
            return None;
        }

        let (path, off, size) = self.paths[self.index].clone();
        self.index += 1;

        let slice = &self.file.as_slice()[off as usize..off as usize + size as usize];
        match decompress_if_needed(slice) {
            Ok(buf) => Some(Ok((path, buf.into_owned()))),
            Err(e) => Some(Err(e)),
        }
    }
}

/// A file entry, either a memory mapped file or an owned buffer.
pub enum FileEntry {
    MappedFile(MappedFile),
    Buffer(Box<[u8]>, FileTime),
}

impl FileEntry {
    /// Creates a reader for the file.
    pub fn as_reader(&self) -> Cursor<&[u8]> {
        match self {
            Self::MappedFile(file) => file.as_reader(),
            Self::Buffer(slice, _) => Cursor::new(slice),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::MappedFile(file) => file.as_slice(),
            Self::Buffer(slice, _) => slice,
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::MappedFile(file) => file.len(),
            Self::Buffer(slice, _) => slice.len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::MappedFile(file) => file.is_empty(),
            Self::Buffer(slice, _) => slice.is_empty(),
        }
    }

    pub fn mtime(&self) -> FileTime {
        match self {
            Self::MappedFile(file) => file.mtime,
            Self::Buffer(_, mtime) => *mtime,
        }
    }
}

/// Information about a file when it was read.
/// Used to determine if a file has changed since it was read (mtime)
/// and if it needs to be written (hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReadInfo {
    pub mtime: FileTime,
    pub hash: u64,
}

impl FileReadInfo {
    pub fn new(entry: &FileEntry) -> Result<Self> {
        let hash = xxh3_64(entry.as_slice());
        Ok(Self { mtime: entry.mtime(), hash })
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
                    return Some(Ok((path, FileEntry::Buffer(buf, rarc.file.mtime))));
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
            Ok(FileEntry::Buffer(_, _)) => todo!(),
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

        match *array_ref!(buf, 0, 4) {
            YAZ0_MAGIC => self.handle_yaz0(file, path),
            YAY0_MAGIC => self.handle_yay0(file, path),
            RARC_MAGIC => self.handle_rarc(file, path),
            _ => Some(Ok((path, FileEntry::MappedFile(file)))),
        }
    }

    fn handle_yaz0(
        &mut self,
        file: MappedFile,
        path: PathBuf,
    ) -> Option<Result<(PathBuf, FileEntry)>> {
        Some(match decompress_yaz0(file.as_slice()) {
            Ok(buf) => Ok((path, FileEntry::Buffer(buf, file.mtime))),
            Err(e) => Err(e),
        })
    }

    fn handle_yay0(
        &mut self,
        file: MappedFile,
        path: PathBuf,
    ) -> Option<Result<(PathBuf, FileEntry)>> {
        Some(match decompress_yay0(file.as_slice()) {
            Ok(buf) => Ok((path, FileEntry::Buffer(buf, file.mtime))),
            Err(e) => Err(e),
        })
    }

    fn handle_rarc(
        &mut self,
        file: MappedFile,
        path: PathBuf,
    ) -> Option<Result<(PathBuf, FileEntry)>> {
        self.rarc = match RarcIterator::new(file, &path) {
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

pub fn touch<P>(path: P) -> std::io::Result<()>
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
