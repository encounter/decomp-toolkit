use std::{
    io,
    io::{BufRead, Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use filetime::FileTime;
use nodtool::nod::DiscStream;
use typed_path::Utf8UnixPath;
use zerocopy::FromZeros;

use crate::{
    array_ref,
    util::wad::{align_up, process_wad, ContentMetadata, WadFile},
    vfs::{
        common::{StaticFile, WindowedFile},
        Vfs, VfsError, VfsFile, VfsFileType, VfsMetadata, VfsResult,
    },
};

#[derive(Clone)]
pub struct WadFs {
    file: Box<dyn VfsFile>,
    wad: WadFile,
    mtime: Option<FileTime>,
}

enum WadFindResult<'a> {
    Root,
    Static(&'a [u8]),
    Content(u16, &'a ContentMetadata),
    Window(u64, u64),
}

impl WadFs {
    pub fn new(mut file: Box<dyn VfsFile>) -> io::Result<Self> {
        let mtime = file.metadata()?.mtime;
        let wad = process_wad(file.as_mut())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self { file, wad, mtime })
    }

    fn find(&self, path: &str) -> Option<WadFindResult> {
        let filename = path.trim_start_matches('/');
        if filename.contains('/') {
            return None;
        }
        if filename.is_empty() {
            return Some(WadFindResult::Root);
        }
        let filename = filename.to_ascii_lowercase();
        if let Some(id) = filename.strip_suffix(".app") {
            if let Ok(content_index) = u16::from_str_radix(id, 16) {
                if let Some(content) = self.wad.contents().get(content_index as usize) {
                    return Some(WadFindResult::Content(content_index, content));
                }
            }
            return None;
        }
        let title_id = hex::encode(self.wad.ticket().title_id);
        match filename.strip_prefix(&title_id) {
            Some(".tik") => Some(WadFindResult::Static(&self.wad.raw_ticket)),
            Some(".tmd") => Some(WadFindResult::Static(&self.wad.raw_tmd)),
            Some(".cert") => Some(WadFindResult::Static(&self.wad.raw_cert_chain)),
            Some(".trailer") => {
                if self.wad.header.footer_size.get() == 0 {
                    return None;
                }
                Some(WadFindResult::Window(
                    self.wad.trailer_offset(),
                    self.wad.header.footer_size.get() as u64,
                ))
            }
            _ => None,
        }
    }
}

impl Vfs for WadFs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        if let Some(result) = self.find(path.as_str()) {
            match result {
                WadFindResult::Root => Err(VfsError::IsADirectory),
                WadFindResult::Static(data) => {
                    Ok(Box::new(StaticFile::new(Arc::from(data), self.mtime)))
                }
                WadFindResult::Content(content_index, content) => {
                    let offset = self.wad.content_offset(content_index);
                    Ok(Box::new(WadContent::new(
                        AesCbcStream::new(
                            self.file.clone(),
                            offset,
                            content.size.get(),
                            &self.wad.title_key,
                            &content.iv(),
                        ),
                        self.mtime,
                    )))
                }
                WadFindResult::Window(offset, len) => {
                    Ok(Box::new(WindowedFile::new(self.file.clone(), offset, len)?))
                }
            }
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool> {
        Ok(self.find(path.as_str()).is_some())
    }

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>> {
        let path = path.as_str().trim_start_matches('/');
        if !path.is_empty() {
            return Err(VfsError::NotFound);
        }
        let title_id = hex::encode(self.wad.ticket().title_id);
        let mut entries = Vec::new();
        entries.push(format!("{title_id}.tik"));
        entries.push(format!("{title_id}.tmd"));
        entries.push(format!("{title_id}.cert"));
        if self.wad.header.footer_size.get() > 0 {
            entries.push(format!("{title_id}.trailer"));
        }
        for content in self.wad.contents() {
            entries.push(format!("{:08x}.app", content.content_index.get()));
        }
        Ok(entries)
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        if let Some(result) = self.find(path.as_str()) {
            match result {
                WadFindResult::Root => {
                    Ok(VfsMetadata { file_type: VfsFileType::Directory, len: 0, mtime: self.mtime })
                }
                WadFindResult::Static(data) => Ok(VfsMetadata {
                    file_type: VfsFileType::File,
                    len: data.len() as u64,
                    mtime: self.mtime,
                }),
                WadFindResult::Content(_, content) => Ok(VfsMetadata {
                    file_type: VfsFileType::File,
                    len: content.size.get(),
                    mtime: self.mtime,
                }),
                WadFindResult::Window(_, len) => {
                    Ok(VfsMetadata { file_type: VfsFileType::File, len, mtime: self.mtime })
                }
            }
        } else {
            Err(VfsError::NotFound)
        }
    }
}

#[derive(Clone)]
enum WadContentInner {
    Stream(AesCbcStream),
    Mapped(Cursor<Arc<[u8]>>),
}

#[derive(Clone)]
struct WadContent {
    inner: WadContentInner,
    mtime: Option<FileTime>,
}

impl WadContent {
    fn new(inner: AesCbcStream, mtime: Option<FileTime>) -> Self {
        Self { inner: WadContentInner::Stream(inner), mtime }
    }

    fn convert_to_mapped(&mut self) -> io::Result<()> {
        match &mut self.inner {
            WadContentInner::Stream(stream) => {
                let pos = stream.stream_position()?;
                stream.seek(SeekFrom::Start(0))?;
                let mut data = <[u8]>::new_box_zeroed_with_elems(stream.len() as usize)
                    .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
                stream.read_exact(&mut data)?;
                let mut cursor = Cursor::new(Arc::from(data));
                cursor.set_position(pos);
                self.inner = WadContentInner::Mapped(cursor);
            }
            WadContentInner::Mapped(_) => {}
        };
        Ok(())
    }
}

impl BufRead for WadContent {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match &mut self.inner {
            WadContentInner::Stream(stream) => stream.fill_buf(),
            WadContentInner::Mapped(data) => data.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.inner {
            WadContentInner::Stream(stream) => stream.consume(amt),
            WadContentInner::Mapped(data) => data.consume(amt),
        }
    }
}

impl Read for WadContent {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            WadContentInner::Stream(stream) => stream.read(buf),
            WadContentInner::Mapped(data) => data.read(buf),
        }
    }
}

impl Seek for WadContent {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            WadContentInner::Stream(stream) => stream.seek(pos),
            WadContentInner::Mapped(data) => data.seek(pos),
        }
    }
}

impl VfsFile for WadContent {
    fn map(&mut self) -> io::Result<&[u8]> {
        self.convert_to_mapped()?;
        match &mut self.inner {
            WadContentInner::Stream(_) => unreachable!(),
            WadContentInner::Mapped(data) => Ok(data.get_ref()),
        }
    }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        match &mut self.inner {
            WadContentInner::Stream(stream) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: stream.len(),
                mtime: self.mtime,
            }),
            WadContentInner::Mapped(data) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: data.get_ref().len() as u64,
                mtime: self.mtime,
            }),
        }
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}

#[derive(Clone)]
struct AesCbcStream {
    inner: Box<dyn VfsFile>,
    position: u64,
    content_offset: u64,
    content_size: u64,
    key: [u8; 0x10],
    init_iv: [u8; 0x10],
    last_iv: [u8; 0x10],
    block_idx: u64,
    block: Box<[u8; 0x200]>,
}

impl AesCbcStream {
    fn new(
        inner: Box<dyn VfsFile>,
        content_offset: u64,
        content_size: u64,
        key: &[u8; 0x10],
        iv: &[u8; 0x10],
    ) -> Self {
        let block = <[u8; 0x200]>::new_box_zeroed().unwrap();
        Self {
            inner,
            position: 0,
            content_offset,
            content_size,
            key: *key,
            init_iv: *iv,
            last_iv: [0u8; 0x10],
            block_idx: u64::MAX,
            block,
        }
    }

    #[inline]
    fn len(&self) -> u64 { self.content_size }

    #[inline]
    fn remaining(&self) -> u64 { self.content_size.saturating_sub(self.position) }
}

impl Read for AesCbcStream {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while !buf.is_empty() {
            let block = self.fill_buf()?;
            if block.is_empty() {
                break;
            }
            let len = buf.len().min(block.len());
            buf[..len].copy_from_slice(&block[..len]);
            buf = &mut buf[len..];
            self.consume(len);
            total += len;
        }
        Ok(total)
    }
}

impl BufRead for AesCbcStream {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position >= self.content_size {
            return Ok(&[]);
        }
        let block_size = self.block.len();
        let current_block = self.position / block_size as u64;
        if current_block != self.block_idx {
            let block_offset = current_block * block_size as u64;
            let mut iv = [0u8; 0x10];
            if current_block == 0 {
                // Use the initial IV for the first block
                self.inner.seek(SeekFrom::Start(self.content_offset))?;
                iv = self.init_iv;
            } else if self.block_idx.checked_add(1) == Some(current_block) {
                // Shortcut to avoid seeking when reading sequentially
                iv = self.last_iv;
            } else {
                // Read the IV from the previous block
                self.inner.seek(SeekFrom::Start(self.content_offset + block_offset - 0x10))?;
                self.inner.read_exact(&mut iv)?;
            }
            let aligned_size = align_up(self.content_size, 0x10);
            let remaining = aligned_size.saturating_sub(block_offset);
            let read = remaining.min(block_size as u64) as usize;
            self.inner.read_exact(&mut self.block[..read])?;
            self.last_iv = *array_ref!(self.block, read - 0x10, 0x10);
            let mut decryptor =
                cbc::Decryptor::<aes::Aes128>::new((&self.key).into(), (&iv).into());
            for aes_block in self.block[..read].chunks_exact_mut(0x10) {
                decryptor.decrypt_block_mut(aes_block.into());
            }
            self.block_idx = current_block;
        }
        let offset = (self.position % block_size as u64) as usize;
        let len = self.remaining().min((block_size - offset) as u64) as usize;
        Ok(&self.block[offset..offset + len])
    }

    fn consume(&mut self, amt: usize) { self.position = self.position.saturating_add(amt as u64); }
}

impl Seek for AesCbcStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => self.content_size.saturating_add_signed(p),
            SeekFrom::Current(p) => self.position.saturating_add_signed(p),
        };
        Ok(self.position)
    }
}
