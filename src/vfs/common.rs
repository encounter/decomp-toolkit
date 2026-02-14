use std::{
    io,
    io::{BufRead, Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

use filetime::FileTime;

use super::{DiscStream, VfsFileType, VfsMetadata};
use crate::vfs::VfsFile;

#[derive(Clone)]
pub struct StaticFile {
    inner: Cursor<Arc<[u8]>>,
    mtime: Option<FileTime>,
}

impl StaticFile {
    pub fn new(data: Arc<[u8]>, mtime: Option<FileTime>) -> Self {
        Self { inner: Cursor::new(data), mtime }
    }
}

impl BufRead for StaticFile {
    fn fill_buf(&mut self) -> io::Result<&[u8]> { self.inner.fill_buf() }

    fn consume(&mut self, amt: usize) { self.inner.consume(amt) }
}

impl Read for StaticFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.read(buf) }
}

impl Seek for StaticFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.inner.seek(pos) }
}

impl VfsFile for StaticFile {
    fn map(&mut self) -> io::Result<&[u8]> { Ok(self.inner.get_ref()) }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        Ok(VfsMetadata {
            file_type: VfsFileType::File,
            len: self.inner.get_ref().len() as u64,
            mtime: self.mtime,
        })
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}
