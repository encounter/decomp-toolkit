mod common;
mod disc;
mod rarc;
mod std_fs;
mod u8_arc;

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    io,
    io::{BufRead, Read, Seek, SeekFrom},
    path::Path,
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
use u8_arc::U8Fs;

use crate::util::{
    ncompress::{YAY0_MAGIC, YAZ0_MAGIC},
    rarc::RARC_MAGIC,
    u8_arc::U8_MAGIC,
};

pub trait Vfs: DynClone + Send + Sync {
    fn open(&mut self, path: &str) -> VfsResult<Box<dyn VfsFile>>;

    fn exists(&mut self, path: &str) -> VfsResult<bool>;

    fn read_dir(&mut self, path: &str) -> VfsResult<Vec<String>>;

    fn metadata(&mut self, path: &str) -> VfsResult<VfsMetadata>;
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
    IoError(io::Error),
    Other(String),
    FileExists,
    DirectoryExists,
}

pub type VfsResult<T, E = VfsError> = Result<T, E>;

impl From<io::Error> for VfsError {
    fn from(e: io::Error) -> Self { VfsError::IoError(e) }
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
            VfsError::IoError(e) => write!(f, "{}", e),
            VfsError::Other(e) => write!(f, "{}", e),
            VfsError::FileExists => write!(f, "File already exists"),
            VfsError::DirectoryExists => write!(f, "Directory already exists"),
        }
    }
}

impl Error for VfsError {}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum FileFormat {
    Regular,
    Compressed(CompressionKind),
    Archive(ArchiveKind),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CompressionKind {
    Yay0,
    Yaz0,
    Nlzss,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ArchiveKind {
    Rarc,
    U8,
    Disc,
}

pub fn detect<R>(file: &mut R) -> io::Result<FileFormat>
where R: Read + Seek + ?Sized {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 4];
    match file.read_exact(&mut magic) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(FileFormat::Regular),
        Err(e) => return Err(e),
    }
    file.seek_relative(-4)?;
    match magic {
        YAY0_MAGIC => Ok(FileFormat::Compressed(CompressionKind::Yay0)),
        YAZ0_MAGIC => Ok(FileFormat::Compressed(CompressionKind::Yaz0)),
        RARC_MAGIC => Ok(FileFormat::Archive(ArchiveKind::Rarc)),
        U8_MAGIC => Ok(FileFormat::Archive(ArchiveKind::U8)),
        _ => {
            let format = nod::Disc::detect(file)?;
            file.seek(SeekFrom::Start(0))?;
            match format {
                Some(_) => Ok(FileFormat::Archive(ArchiveKind::Disc)),
                None => Ok(FileFormat::Regular),
            }
        }
    }
}

pub fn open_path(path: &Path, auto_decompress: bool) -> anyhow::Result<Box<dyn VfsFile>> {
    open_path_fs(Box::new(StdFs), path, auto_decompress)
}

pub fn open_path_fs(
    mut fs: Box<dyn Vfs>,
    path: &Path,
    auto_decompress: bool,
) -> anyhow::Result<Box<dyn VfsFile>> {
    let str = path.to_str().ok_or_else(|| anyhow!("Path is not valid UTF-8"))?;
    let mut split = str.split(':').peekable();
    let mut within = String::new();
    loop {
        let path = split.next().unwrap();
        let mut file = fs
            .open(path)
            .with_context(|| format!("Failed to open {}", format_path(path, &within)))?;
        match detect(file.as_mut()).with_context(|| {
            format!("Failed to detect file type for {}", format_path(path, &within))
        })? {
            FileFormat::Regular => {
                return match split.next() {
                    None => Ok(file),
                    Some(segment) => {
                        if split.next().is_some() {
                            return Err(anyhow!(
                                "{} is not an archive",
                                format_path(path, &within)
                            ));
                        }
                        match segment {
                            "nlzss" => Ok(decompress_file(file, CompressionKind::Nlzss)
                                .with_context(|| {
                                    format!(
                                        "Failed to decompress {} with NLZSS",
                                        format_path(path, &within)
                                    )
                                })?),
                            "yay0" => Ok(decompress_file(file, CompressionKind::Yay0)
                                .with_context(|| {
                                    format!(
                                        "Failed to decompress {} with Yay0",
                                        format_path(path, &within)
                                    )
                                })?),
                            "yaz0" => Ok(decompress_file(file, CompressionKind::Yaz0)
                                .with_context(|| {
                                    format!(
                                        "Failed to decompress {} with Yaz0",
                                        format_path(path, &within)
                                    )
                                })?),
                            _ => Err(anyhow!("{} is not an archive", format_path(path, &within))),
                        }
                    }
                }
            }
            FileFormat::Compressed(kind) => {
                return if split.peek().is_none() {
                    if auto_decompress {
                        Ok(decompress_file(file, kind).with_context(|| {
                            format!("Failed to decompress {}", format_path(path, &within))
                        })?)
                    } else {
                        Ok(file)
                    }
                } else {
                    Err(anyhow!("{} is not an archive", format_path(path, &within)))
                };
            }
            FileFormat::Archive(kind) => {
                if split.peek().is_none() {
                    return Ok(file);
                } else {
                    fs = open_fs(file, kind).with_context(|| {
                        format!("Failed to open container {}", format_path(path, &within))
                    })?;
                    if !within.is_empty() {
                        within.push(':');
                    }
                    within.push_str(path);
                }
            }
        }
    }
}

pub fn open_fs(mut file: Box<dyn VfsFile>, kind: ArchiveKind) -> io::Result<Box<dyn Vfs>> {
    let metadata = file.metadata()?;
    match kind {
        ArchiveKind::Rarc => Ok(Box::new(RarcFs::new(file)?)),
        ArchiveKind::U8 => Ok(Box::new(U8Fs::new(file)?)),
        ArchiveKind::Disc => {
            let disc = nod::Disc::new_stream(file.into_disc_stream()).map_err(nod_to_io_error)?;
            let partition =
                disc.open_partition_kind(nod::PartitionKind::Data).map_err(nod_to_io_error)?;
            Ok(Box::new(DiscFs::new(partition, metadata.mtime)?))
        }
    }
}

pub fn decompress_file(
    mut file: Box<dyn VfsFile>,
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
            let result = nintendo_lz::decompress(&mut file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Box::new(StaticFile::new(Arc::from(result.as_slice()), metadata.mtime)))
        }
    }
}

fn format_path(path: &str, within: &str) -> String {
    if within.is_empty() {
        format!("'{}'", path)
    } else {
        format!("'{}' (within '{}')", path, within)
    }
}
