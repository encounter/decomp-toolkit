mod common;
mod disc;
mod rarc;
mod std_fs;
mod u8_arc;
mod wad;

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    io,
    io::{BufRead, Read, Seek, SeekFrom},
    sync::Arc,
};

use anyhow::{anyhow, Context};
use common::{StaticFile, WindowedFile};
use disc::{nod_to_io_error, DiscFs};
use dyn_clone::DynClone;
use filetime::FileTime;
use nodtool::{nod, nod::DiscStream};
use rarc::RarcFs;
pub use std_fs::StdFs;
use typed_path::{Utf8NativePath, Utf8UnixPath, Utf8UnixPathBuf};
use u8_arc::U8Fs;
use wad::WadFs;

use crate::util::{
    ncompress::{YAY0_MAGIC, YAZ0_MAGIC},
    nlzss,
    rarc::RARC_MAGIC,
    u8_arc::U8_MAGIC,
    wad::WAD_MAGIC,
};

pub trait Vfs: DynClone + Send + Sync {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>>;

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool>;

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>>;

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata>;
}

dyn_clone::clone_trait_object!(Vfs);

pub trait VfsFile: DiscStream + BufRead {
    fn map(&mut self) -> io::Result<&[u8]>;

    fn metadata(&mut self) -> io::Result<VfsMetadata>;

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream>;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum VfsFileType {
    File,
    Directory,
}

pub struct VfsMetadata {
    pub file_type: VfsFileType,
    pub len: u64,
    pub mtime: Option<FileTime>,
}

impl VfsMetadata {
    pub fn is_file(&self) -> bool { self.file_type == VfsFileType::File }

    pub fn is_dir(&self) -> bool { self.file_type == VfsFileType::Directory }
}

dyn_clone::clone_trait_object!(VfsFile);

#[derive(Debug)]
pub enum VfsError {
    NotFound,
    NotADirectory,
    IsADirectory,
    IoError(io::Error),
    Other(String),
}

pub type VfsResult<T, E = VfsError> = Result<T, E>;

impl From<io::Error> for VfsError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => VfsError::NotFound,
            // TODO: stabilized in Rust 1.83
            // io::ErrorKind::NotADirectory => VfsError::NotADirectory,
            // io::ErrorKind::IsADirectory => VfsError::IsADirectory,
            _ => VfsError::IoError(e),
        }
    }
}

impl From<String> for VfsError {
    fn from(e: String) -> Self { VfsError::Other(e) }
}

impl From<&str> for VfsError {
    fn from(e: &str) -> Self { VfsError::Other(e.to_string()) }
}

impl Display for VfsError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            VfsError::NotFound => write!(f, "File or directory not found"),
            VfsError::IoError(e) => write!(f, "{e}"),
            VfsError::Other(e) => write!(f, "{e}"),
            VfsError::NotADirectory => write!(f, "Path is a file, not a directory"),
            VfsError::IsADirectory => write!(f, "Path is a directory, not a file"),
        }
    }
}

impl Error for VfsError {}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileFormat {
    Regular,
    Compressed(CompressionKind),
    Archive(ArchiveKind),
}

impl Display for FileFormat {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            FileFormat::Regular => write!(f, "File"),
            FileFormat::Compressed(kind) => write!(f, "Compressed: {kind}"),
            FileFormat::Archive(kind) => write!(f, "Archive: {kind}"),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CompressionKind {
    Yay0,
    Yaz0,
    Nlzss,
}

impl Display for CompressionKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CompressionKind::Yay0 => write!(f, "Yay0"),
            CompressionKind::Yaz0 => write!(f, "Yaz0"),
            CompressionKind::Nlzss => write!(f, "NLZSS"),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ArchiveKind {
    Rarc,
    U8,
    Disc(nod::Format),
    Wad,
}

impl Display for ArchiveKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ArchiveKind::Rarc => write!(f, "RARC"),
            ArchiveKind::U8 => write!(f, "U8"),
            ArchiveKind::Disc(format) => write!(f, "Disc ({format})"),
            ArchiveKind::Wad => write!(f, "WAD"),
        }
    }
}

pub fn detect<R>(file: &mut R) -> io::Result<FileFormat>
where R: Read + Seek + ?Sized {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    match file.read_exact(&mut magic) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(FileFormat::Regular),
        Err(e) => return Err(e),
    }
    file.seek_relative(-8)?;
    match magic {
        _ if magic.starts_with(&YAY0_MAGIC) => Ok(FileFormat::Compressed(CompressionKind::Yay0)),
        _ if magic.starts_with(&YAZ0_MAGIC) => Ok(FileFormat::Compressed(CompressionKind::Yaz0)),
        _ if magic.starts_with(&RARC_MAGIC) => Ok(FileFormat::Archive(ArchiveKind::Rarc)),
        _ if magic.starts_with(&U8_MAGIC) => Ok(FileFormat::Archive(ArchiveKind::U8)),
        WAD_MAGIC => Ok(FileFormat::Archive(ArchiveKind::Wad)),
        _ => {
            let format = nod::Disc::detect(file)?;
            file.seek(SeekFrom::Start(0))?;
            match format {
                Some(format) => Ok(FileFormat::Archive(ArchiveKind::Disc(format))),
                None => Ok(FileFormat::Regular),
            }
        }
    }
}

pub enum OpenResult {
    File(Box<dyn VfsFile>, Utf8UnixPathBuf),
    Directory(Box<dyn Vfs>, Utf8UnixPathBuf),
}

pub fn open_path(path: &Utf8NativePath, auto_decompress: bool) -> anyhow::Result<OpenResult> {
    open_path_with_fs(Box::new(StdFs), path, auto_decompress)
}

pub fn open_path_with_fs(
    mut fs: Box<dyn Vfs>,
    path: &Utf8NativePath,
    auto_decompress: bool,
) -> anyhow::Result<OpenResult> {
    let path = path.with_unix_encoding();
    let mut split = path.as_str().split(':').peekable();
    let mut current_path = String::new();
    let mut file: Option<Box<dyn VfsFile>> = None;
    let mut segment = Utf8UnixPath::new("");
    loop {
        // Open the next segment if necessary
        if file.is_none() {
            segment = Utf8UnixPath::new(split.next().unwrap());
            if !current_path.is_empty() {
                current_path.push(':');
            }
            current_path.push_str(segment.as_str());
            let file_type = match fs.metadata(segment) {
                Ok(metadata) => metadata.file_type,
                Err(VfsError::NotFound) => return Err(anyhow!("{} not found", current_path)),
                Err(e) => return Err(e).context(format!("Failed to open {current_path}")),
            };
            match file_type {
                VfsFileType::File => {
                    file = Some(
                        fs.open(segment)
                            .with_context(|| format!("Failed to open {current_path}"))?,
                    );
                }
                VfsFileType::Directory => {
                    return if split.peek().is_some() {
                        Err(anyhow!("{} is not a file", current_path))
                    } else {
                        Ok(OpenResult::Directory(fs, segment.to_path_buf()))
                    }
                }
            }
        }
        let mut current_file = file.take().unwrap();
        let format = detect(current_file.as_mut())
            .with_context(|| format!("Failed to detect file type for {current_path}"))?;
        if let Some(&next) = split.peek() {
            match next {
                "nlzss" => {
                    split.next();
                    file = Some(
                        decompress_file(current_file.as_mut(), CompressionKind::Nlzss)
                            .with_context(|| {
                                format!("Failed to decompress {current_path} with NLZSS")
                            })?,
                    );
                }
                "yay0" => {
                    split.next();
                    file = Some(
                        decompress_file(current_file.as_mut(), CompressionKind::Yay0)
                            .with_context(|| {
                                format!("Failed to decompress {current_path} with Yay0")
                            })?,
                    );
                }
                "yaz0" => {
                    split.next();
                    file = Some(
                        decompress_file(current_file.as_mut(), CompressionKind::Yaz0)
                            .with_context(|| {
                                format!("Failed to decompress {current_path} with Yaz0")
                            })?,
                    );
                }
                _ => match format {
                    FileFormat::Regular => {
                        return Err(anyhow!("{} is not an archive", current_path))
                    }
                    FileFormat::Compressed(kind) => {
                        file = Some(
                            decompress_file(current_file.as_mut(), kind)
                                .with_context(|| format!("Failed to decompress {current_path}"))?,
                        );
                        // Continue the loop to detect the new format
                    }
                    FileFormat::Archive(kind) => {
                        fs = open_fs(current_file, kind)
                            .with_context(|| format!("Failed to open container {current_path}"))?;
                        // Continue the loop to open the next segment
                    }
                },
            }
        } else {
            // No more segments, return as-is
            return match format {
                FileFormat::Compressed(kind) if auto_decompress => Ok(OpenResult::File(
                    decompress_file(current_file.as_mut(), kind)
                        .with_context(|| format!("Failed to decompress {current_path}"))?,
                    segment.to_path_buf(),
                )),
                _ => Ok(OpenResult::File(current_file, segment.to_path_buf())),
            };
        }
    }
}

pub fn open_file(path: &Utf8NativePath, auto_decompress: bool) -> anyhow::Result<Box<dyn VfsFile>> {
    open_file_with_fs(Box::new(StdFs), path, auto_decompress)
}

pub fn open_file_with_fs(
    fs: Box<dyn Vfs>,
    path: &Utf8NativePath,
    auto_decompress: bool,
) -> anyhow::Result<Box<dyn VfsFile>> {
    match open_path_with_fs(fs, path, auto_decompress)? {
        OpenResult::File(file, _) => Ok(file),
        OpenResult::Directory(_, _) => Err(VfsError::IsADirectory.into()),
    }
}

pub fn open_fs(mut file: Box<dyn VfsFile>, kind: ArchiveKind) -> io::Result<Box<dyn Vfs>> {
    let metadata = file.metadata()?;
    match kind {
        ArchiveKind::Rarc => Ok(Box::new(RarcFs::new(file)?)),
        ArchiveKind::U8 => Ok(Box::new(U8Fs::new(file)?)),
        ArchiveKind::Disc(_) => {
            let disc =
                Arc::new(nod::Disc::new_stream(file.into_disc_stream()).map_err(nod_to_io_error)?);
            let partition =
                disc.open_partition_kind(nod::PartitionKind::Data).map_err(nod_to_io_error)?;
            Ok(Box::new(DiscFs::new(disc, partition, metadata.mtime)?))
        }
        ArchiveKind::Wad => Ok(Box::new(WadFs::new(file)?)),
    }
}

pub fn decompress_file(
    file: &mut dyn VfsFile,
    kind: CompressionKind,
) -> io::Result<Box<dyn VfsFile>> {
    let metadata = file.metadata()?;
    match kind {
        CompressionKind::Yay0 => {
            let data = file.map()?;
            let result = orthrus_ncompress::yay0::Yay0::decompress_from(data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Box::new(StaticFile::new(Arc::from(result), metadata.mtime)))
        }
        CompressionKind::Yaz0 => {
            let data = file.map()?;
            let result = orthrus_ncompress::yaz0::Yaz0::decompress_from(data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Box::new(StaticFile::new(Arc::from(result), metadata.mtime)))
        }
        CompressionKind::Nlzss => {
            let result = nlzss::decompress(file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Box::new(StaticFile::new(Arc::from(result.as_slice()), metadata.mtime)))
        }
    }
}

#[inline]
pub fn next_non_empty<'a>(iter: &mut impl Iterator<Item = &'a str>) -> &'a str {
    loop {
        match iter.next() {
            Some("") => continue,
            Some(next) => break next,
            None => break "",
        }
    }
}
