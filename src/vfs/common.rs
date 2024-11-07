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

#[derive(Clone)]
pub struct WindowedFile {
    base: Box<dyn VfsFile>,
    pos: u64,
    begin: u64,
    end: u64,
}

impl WindowedFile {
    pub fn new(mut base: Box<dyn VfsFile>, offset: u64, size: u64) -> io::Result<Self> {
        base.seek(SeekFrom::Start(offset))?;
        Ok(Self { base, pos: offset, begin: offset, end: offset + size })
    }

    #[inline]
    pub fn len(&self) -> u64 { self.end - self.begin }
}

impl BufRead for WindowedFile {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let buf = self.base.fill_buf()?;
        let remaining = self.end.saturating_sub(self.pos);
        Ok(&buf[..buf.len().min(remaining as usize)])
    }

    fn consume(&mut self, amt: usize) {
        let remaining = self.end.saturating_sub(self.pos);
        let amt = amt.min(remaining as usize);
        self.base.consume(amt);
        self.pos += amt as u64;
    }
}

impl Read for WindowedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.end.saturating_sub(self.pos);
        if remaining == 0 {
            return Ok(0);
        }
        let len = buf.len().min(remaining as usize);
        self.base.read(&mut buf[..len])
    }
}

impl Seek for WindowedFile {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut pos = match pos {
            SeekFrom::Start(p) => self.begin + p,
            SeekFrom::End(p) => self.end.saturating_add_signed(p),
            SeekFrom::Current(p) => self.pos.saturating_add_signed(p),
        };
        if pos < self.begin {
            pos = self.begin;
        } else if pos > self.end {
            pos = self.end;
        }
        let result = self.base.seek(SeekFrom::Start(pos))?;
        self.pos = result;
        Ok(result - self.begin)
    }

    #[inline]
    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos - self.begin) }
}

impl VfsFile for WindowedFile {
    fn map(&mut self) -> io::Result<&[u8]> {
        let buf = self.base.map()?;
        Ok(&buf[self.pos as usize..self.end as usize])
    }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        let metadata = self.base.metadata()?;
        Ok(VfsMetadata { file_type: VfsFileType::File, len: self.len(), mtime: metadata.mtime })
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}
