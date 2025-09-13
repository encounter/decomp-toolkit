use std::{
    io,
    io::{BufRead, Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

use filetime::FileTime;
use nodtool::{
    nod,
    nod::{Disc, DiscStream, Fst, NodeKind, OwnedFileStream, PartitionBase, PartitionMeta},
};
use typed_path::Utf8UnixPath;
use zerocopy::{FromZeros, IntoBytes};

use super::{
    next_non_empty, StaticFile, Vfs, VfsError, VfsFile, VfsFileType, VfsMetadata, VfsResult,
};

#[derive(Clone)]
pub struct DiscFs {
    disc: Arc<Disc>,
    base: Box<dyn PartitionBase>,
    meta: Box<PartitionMeta>,
    mtime: Option<FileTime>,
}

enum SpecialDir {
    Root,
    Sys,
    Disc,
}

enum DiscNode<'a> {
    None,
    Special(SpecialDir),
    Node(Fst<'a>, usize, nod::Node),
    Static(&'a [u8]),
}

impl DiscFs {
    pub fn new(
        disc: Arc<Disc>,
        mut base: Box<dyn PartitionBase>,
        mtime: Option<FileTime>,
    ) -> io::Result<Self> {
        let meta = base.meta().map_err(nod_to_io_error)?;
        Ok(Self { disc, base, meta, mtime })
    }

    fn find(&self, path: &Utf8UnixPath) -> VfsResult<DiscNode<'_>> {
        let path = path.as_str().trim_matches('/');
        let mut split = path.split('/');
        let mut segment = next_non_empty(&mut split);
        match segment.to_ascii_lowercase().as_str() {
            "" => Ok(DiscNode::Special(SpecialDir::Root)),
            "files" => {
                let fst = Fst::new(&self.meta.raw_fst)?;
                if next_non_empty(&mut split).is_empty() {
                    let root = fst.nodes[0];
                    return Ok(DiscNode::Node(fst, 0, root));
                }
                let remainder = &path[segment.len() + 1..];
                match fst.find(remainder) {
                    Some((idx, node)) => Ok(DiscNode::Node(fst, idx, node)),
                    None => Ok(DiscNode::None),
                }
            }
            "sys" => {
                segment = next_non_empty(&mut split);
                // No directories in sys
                if !next_non_empty(&mut split).is_empty() {
                    return Ok(DiscNode::None);
                }
                match segment.to_ascii_lowercase().as_str() {
                    "" => Ok(DiscNode::Special(SpecialDir::Sys)),
                    "boot.bin" => Ok(DiscNode::Static(self.meta.raw_boot.as_slice())),
                    "bi2.bin" => Ok(DiscNode::Static(self.meta.raw_bi2.as_slice())),
                    "apploader.img" => Ok(DiscNode::Static(self.meta.raw_apploader.as_ref())),
                    "fst.bin" => Ok(DiscNode::Static(self.meta.raw_fst.as_ref())),
                    "main.dol" => Ok(DiscNode::Static(self.meta.raw_dol.as_ref())),
                    _ => Ok(DiscNode::None),
                }
            }
            "disc" => {
                if !self.disc.header().is_wii() {
                    return Ok(DiscNode::None);
                }
                segment = next_non_empty(&mut split);
                // No directories in disc
                if !next_non_empty(&mut split).is_empty() {
                    return Ok(DiscNode::None);
                }
                match segment.to_ascii_lowercase().as_str() {
                    "" => Ok(DiscNode::Special(SpecialDir::Disc)),
                    "header.bin" => Ok(DiscNode::Static(&self.disc.header().as_bytes()[..0x100])),
                    "region.bin" => {
                        Ok(DiscNode::Static(self.disc.region().ok_or(VfsError::NotFound)?))
                    }
                    _ => Ok(DiscNode::None),
                }
            }
            "ticket.bin" => {
                Ok(DiscNode::Static(self.meta.raw_ticket.as_deref().ok_or(VfsError::NotFound)?))
            }
            "tmd.bin" => {
                Ok(DiscNode::Static(self.meta.raw_tmd.as_deref().ok_or(VfsError::NotFound)?))
            }
            "cert.bin" => {
                Ok(DiscNode::Static(self.meta.raw_cert_chain.as_deref().ok_or(VfsError::NotFound)?))
            }
            "h3.bin" => {
                Ok(DiscNode::Static(self.meta.raw_h3_table.as_deref().ok_or(VfsError::NotFound)?))
            }
            _ => Ok(DiscNode::None),
        }
    }
}

impl Vfs for DiscFs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        match self.find(path)? {
            DiscNode::None => Err(VfsError::NotFound),
            DiscNode::Special(_) => Err(VfsError::IsADirectory),
            DiscNode::Node(_, _, node) => match node.kind() {
                NodeKind::File => {
                    if node.length() > 2048 {
                        let file = self.base.clone().into_open_file(node)?;
                        Ok(Box::new(DiscFile::new(file, self.mtime)))
                    } else {
                        let len = node.length() as usize;
                        let mut file = self.base.open_file(node)?;
                        let mut data = vec![0u8; len];
                        file.read_exact(&mut data)?;
                        Ok(Box::new(StaticFile::new(Arc::from(data.as_slice()), self.mtime)))
                    }
                }
                NodeKind::Directory => Err(VfsError::IsADirectory),
                NodeKind::Invalid => Err(VfsError::from("FST: Invalid node kind")),
            },
            DiscNode::Static(data) => Ok(Box::new(StaticFile::new(Arc::from(data), self.mtime))),
        }
    }

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool> {
        Ok(!matches!(self.find(path)?, DiscNode::None))
    }

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>> {
        match self.find(path)? {
            DiscNode::None => Err(VfsError::NotFound),
            DiscNode::Special(SpecialDir::Root) => {
                let mut entries = vec!["files".to_string(), "sys".to_string()];
                if self.disc.header().is_wii() {
                    entries.push("disc".to_string());
                }
                if self.meta.raw_cert_chain.is_some() {
                    entries.push("cert.bin".to_string());
                }
                if self.meta.raw_h3_table.is_some() {
                    entries.push("h3.bin".to_string());
                }
                if self.meta.raw_ticket.is_some() {
                    entries.push("ticket.bin".to_string());
                }
                if self.meta.raw_tmd.is_some() {
                    entries.push("tmd.bin".to_string());
                }
                Ok(entries)
            }
            DiscNode::Special(SpecialDir::Sys) => Ok(vec![
                "boot.bin".to_string(),
                "bi2.bin".to_string(),
                "apploader.img".to_string(),
                "fst.bin".to_string(),
                "main.dol".to_string(),
            ]),
            DiscNode::Special(SpecialDir::Disc) => {
                let mut entries = Vec::new();
                if self.disc.header().is_wii() {
                    entries.push("header.bin".to_string());
                    if self.disc.region().is_some() {
                        entries.push("region.bin".to_string());
                    }
                }
                Ok(entries)
            }
            DiscNode::Node(fst, idx, node) => {
                match node.kind() {
                    NodeKind::File => return Err(VfsError::NotADirectory),
                    NodeKind::Directory => {}
                    NodeKind::Invalid => return Err(VfsError::from("FST: Invalid node kind")),
                }
                let mut entries = Vec::new();
                let mut idx = idx + 1;
                let end = node.length() as usize;
                while idx < end {
                    let child = fst
                        .nodes
                        .get(idx)
                        .copied()
                        .ok_or_else(|| VfsError::from("FST: Node index out of bounds"))?;
                    entries.push(fst.get_name(child)?.to_string());
                    if child.is_dir() {
                        idx = child.length() as usize;
                    } else {
                        idx += 1;
                    }
                }
                Ok(entries)
            }
            DiscNode::Static(_) => Err(VfsError::NotADirectory),
        }
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        match self.find(path)? {
            DiscNode::None => Err(VfsError::NotFound),
            DiscNode::Special(_) => {
                Ok(VfsMetadata { file_type: VfsFileType::Directory, len: 0, mtime: self.mtime })
            }
            DiscNode::Node(_, _, node) => {
                let (file_type, len) = match node.kind() {
                    NodeKind::File => (VfsFileType::File, node.length()),
                    NodeKind::Directory => (VfsFileType::Directory, 0),
                    NodeKind::Invalid => return Err(VfsError::from("FST: Invalid node kind")),
                };
                Ok(VfsMetadata { file_type, len, mtime: self.mtime })
            }
            DiscNode::Static(data) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: data.len() as u64,
                mtime: self.mtime,
            }),
        }
    }
}

#[derive(Clone)]
enum DiscFileInner {
    Stream(OwnedFileStream),
    Mapped(Cursor<Arc<[u8]>>),
}

#[derive(Clone)]
struct DiscFile {
    inner: DiscFileInner,
    mtime: Option<FileTime>,
}

impl DiscFile {
    pub fn new(file: OwnedFileStream, mtime: Option<FileTime>) -> Self {
        Self { inner: DiscFileInner::Stream(file), mtime }
    }

    fn convert_to_mapped(&mut self) -> io::Result<()> {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => {
                let pos = stream.stream_position()?;
                stream.seek(SeekFrom::Start(0))?;
                let mut data = <[u8]>::new_box_zeroed_with_elems(stream.len() as usize)
                    .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
                stream.read_exact(&mut data)?;
                let mut cursor = Cursor::new(Arc::from(data));
                cursor.set_position(pos);
                self.inner = DiscFileInner::Mapped(cursor);
            }
            DiscFileInner::Mapped(_) => {}
        };
        Ok(())
    }
}

impl BufRead for DiscFile {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => stream.fill_buf(),
            DiscFileInner::Mapped(data) => data.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => stream.consume(amt),
            DiscFileInner::Mapped(data) => data.consume(amt),
        }
    }
}

impl Read for DiscFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => stream.read(buf),
            DiscFileInner::Mapped(data) => data.read(buf),
        }
    }
}

impl Seek for DiscFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => stream.seek(pos),
            DiscFileInner::Mapped(data) => data.seek(pos),
        }
    }
}

impl VfsFile for DiscFile {
    fn map(&mut self) -> io::Result<&[u8]> {
        self.convert_to_mapped()?;
        match &mut self.inner {
            DiscFileInner::Stream(_) => unreachable!(),
            DiscFileInner::Mapped(data) => Ok(data.get_ref()),
        }
    }

    fn metadata(&mut self) -> io::Result<VfsMetadata> {
        match &mut self.inner {
            DiscFileInner::Stream(stream) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: stream.len(),
                mtime: self.mtime,
            }),
            DiscFileInner::Mapped(data) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: data.get_ref().len() as u64,
                mtime: self.mtime,
            }),
        }
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}

pub fn nod_to_io_error(e: nod::Error) -> io::Error {
    match e {
        nod::Error::Io(msg, e) => io::Error::new(e.kind(), format!("{msg}: {e}")),
        e => io::Error::new(io::ErrorKind::InvalidData, e),
    }
}
