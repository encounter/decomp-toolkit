use std::{
    io,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use filetime::FileTime;

use super::{DiscStream, Vfs, VfsFile, VfsFileType, VfsMetadata, VfsResult};

#[derive(Clone)]
pub struct StdFs;

impl Vfs for StdFs {
    fn open(&mut self, path: &str) -> VfsResult<Box<dyn VfsFile>> {
        let mut file = StdFile::new(PathBuf::from(path));
        file.file()?; // Open the file now to check for errors
        Ok(Box::new(file))
    }

    fn exists(&mut self, path: &str) -> VfsResult<bool> { Ok(Path::new(path).exists()) }

    fn read_dir(&mut self, path: &str) -> VfsResult<Vec<String>> {
        let entries = std::fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    fn metadata(&mut self, path: &str) -> VfsResult<VfsMetadata> {
        let metadata = std::fs::metadata(path)?;
        Ok(VfsMetadata {
            file_type: if metadata.is_dir() { VfsFileType::Directory } else { VfsFileType::File },
            len: metadata.len(),
            mtime: Some(FileTime::from_last_modification_time(&metadata)),
        })
    }
}

pub struct StdFile {
    path: PathBuf,
    file: Option<BufReader<std::fs::File>>,
    mmap: Option<memmap2::Mmap>,
}

impl Clone for StdFile {
    #[inline]
    fn clone(&self) -> Self { Self { path: self.path.clone(), file: None, mmap: None } }
}

impl StdFile {
    #[inline]
    pub fn new(path: PathBuf) -> Self { StdFile { path, file: None, mmap: None } }

    pub fn file(&mut self) -> io::Result<&mut BufReader<std::fs::File>> {
        if self.file.is_none() {
            self.file = Some(BufReader::new(std::fs::File::open(&self.path)?));
        }
        Ok(self.file.as_mut().unwrap())
    }
}

impl BufRead for StdFile {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> { self.file()?.fill_buf() }

    #[inline]
    fn consume(&mut self, amt: usize) {
        if let Ok(file) = self.file() {
            file.consume(amt);
        }
    }
}

impl Read for StdFile {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.file()?.read(buf) }
}

impl Seek for StdFile {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.file()?.seek(pos) }
}

impl VfsFile for StdFile {
    fn map(&mut self) -> io::Result<&[u8]> {
        if self.file.is_none() {
            self.file = Some(BufReader::new(std::fs::File::open(&self.path)?));
        }
        if self.mmap.is_none() {
            self.mmap = Some(unsafe { memmap2::Mmap::map(self.file.as_ref().unwrap().get_ref())? });
        }
        Ok(self.mmap.as_ref().unwrap())
    }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        let metadata = std::fs::metadata(&self.path)?;
        Ok(VfsMetadata {
            file_type: if metadata.is_dir() { VfsFileType::Directory } else { VfsFileType::File },
            len: metadata.len(),
            mtime: Some(FileTime::from_last_modification_time(&metadata)),
        })
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}
