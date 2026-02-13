use std::io;

use typed_path::Utf8UnixPath;

use super::{Vfs, VfsError, VfsFile, VfsFileType, VfsMetadata, VfsResult, WindowedFile};
use crate::util::u8_arc::{U8NodeKind, U8View};

#[derive(Clone)]
pub struct U8Fs {
    file: Box<dyn VfsFile>,
}

impl U8Fs {
    pub fn new(file: Box<dyn VfsFile>) -> io::Result<Self> { Ok(Self { file }) }

    fn view(&mut self) -> io::Result<U8View<'_>> {
        let data = self.file.map()?;
        U8View::new(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Vfs for U8Fs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        let view = self.view()?;
        match view.find(path) {
            Some((_, node)) => match node.kind() {
                U8NodeKind::File => {
                    let offset = node.offset() as u64;
                    let len = node.length() as u64;
                    let file = WindowedFile::new(self.file.clone(), offset, len)?;
                    Ok(Box::new(file))
                }
                U8NodeKind::Directory => Err(VfsError::IsADirectory),
                U8NodeKind::Invalid => Err(VfsError::from("U8: Invalid node kind")),
            },
            None => Err(VfsError::NotFound),
        }
    }

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool> {
        let view = self.view()?;
        Ok(view.find(path).is_some())
    }

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>> {
        let view = self.view()?;
        match view.find(path) {
            Some((idx, node)) => match node.kind() {
                U8NodeKind::File => Err(VfsError::NotADirectory),
                U8NodeKind::Directory => {
                    let mut entries = Vec::new();
                    let mut idx = idx + 1;
                    let end = node.length() as usize;
                    while idx < end {
                        let child = view.nodes.get(idx).copied().ok_or(VfsError::NotFound)?;
                        entries.push(view.get_name(child)?.to_string());
                        if child.is_dir() {
                            idx = child.length() as usize;
                        } else {
                            idx += 1;
                        }
                    }
                    Ok(entries)
                }
                U8NodeKind::Invalid => Err(VfsError::from("U8: Invalid node kind")),
            },
            None => Err(VfsError::NotFound),
        }
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        let metdata = self.file.metadata()?;
        let view = self.view()?;
        match view.find(path) {
            Some((_, node)) => match node.kind() {
                U8NodeKind::File => Ok(VfsMetadata {
                    file_type: VfsFileType::File,
                    len: node.length() as u64,
                    mtime: metdata.mtime,
                }),
                U8NodeKind::Directory => Ok(VfsMetadata {
                    file_type: VfsFileType::Directory,
                    len: 0,
                    mtime: metdata.mtime,
                }),
                U8NodeKind::Invalid => Err(VfsError::from("U8: Invalid node kind")),
            },
            None => Err(VfsError::NotFound),
        }
    }
}
