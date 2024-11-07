use std::{
    fs, io,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
};

use filetime::FileTime;
use typed_path::{Utf8NativePathBuf, Utf8UnixPath};

use super::{DiscStream, Vfs, VfsFile, VfsFileType, VfsMetadata, VfsResult};

#[derive(Clone)]
pub struct StdFs;

impl Vfs for StdFs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        let mut file = StdFile::new(path.with_encoding());
        file.file()?; // Open the file now to check for errors
        Ok(Box::new(file))
    }

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool> {
        Ok(fs::exists(path.with_encoding())?)
    }

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>> {
        let entries = fs::read_dir(path.with_encoding())?
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        let metadata = fs::metadata(path.with_encoding())?;
        Ok(VfsMetadata {
            file_type: if metadata.is_dir() { VfsFileType::Directory } else { VfsFileType::File },
            len: metadata.len(),
            mtime: Some(FileTime::from_last_modification_time(&metadata)),
        })
    }
}

pub struct StdFile {
    path: Utf8NativePathBuf,
    file: Option<BufReader<fs::File>>,
    mmap: Option<memmap2::Mmap>,
}

impl Clone for StdFile {
    #[inline]
    fn clone(&self) -> Self { Self { path: self.path.clone(), file: None, mmap: None } }
}

impl StdFile {
    #[inline]
    pub fn new(path: Utf8NativePathBuf) -> Self { StdFile { path, file: None, mmap: None } }

    pub fn file(&mut self) -> io::Result<&mut BufReader<fs::File>> {
        Ok(match self.file {
            Some(ref mut file) => file,
            None => self.file.insert(BufReader::new(fs::File::open(&self.path)?)),
        })
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
        let file = match self.file {
            Some(ref mut file) => file,
            None => self.file.insert(BufReader::new(fs::File::open(&self.path)?)),
        };
        let mmap = match self.mmap {
            Some(ref mmap) => mmap,
            None => self.mmap.insert(unsafe { memmap2::Mmap::map(file.get_ref())? }),
        };
        Ok(mmap)
    }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        let metadata = fs::metadata(&self.path)?;
        Ok(VfsMetadata {
            file_type: if metadata.is_dir() { VfsFileType::Directory } else { VfsFileType::File },
            len: metadata.len(),
            mtime: Some(FileTime::from_last_modification_time(&metadata)),
        })
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}
