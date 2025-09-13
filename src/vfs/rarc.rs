use std::io;

use typed_path::Utf8UnixPath;

use super::{Vfs, VfsError, VfsFile, VfsFileType, VfsMetadata, VfsResult, WindowedFile};
use crate::util::rarc::{RarcNodeKind, RarcView};

#[derive(Clone)]
pub struct RarcFs {
    file: Box<dyn VfsFile>,
}

impl RarcFs {
    pub fn new(file: Box<dyn VfsFile>) -> io::Result<Self> { Ok(Self { file }) }

    fn view(&mut self) -> io::Result<RarcView<'_>> {
        let data = self.file.map()?;
        RarcView::new(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Vfs for RarcFs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        let view = self.view()?;
        match view.find(path) {
            Some(RarcNodeKind::File(_, node)) => {
                let offset = view.header.header_len() as u64
                    + view.header.data_offset() as u64
                    + node.data_offset() as u64;
                let len = node.data_length() as u64;
                let file = WindowedFile::new(self.file.clone(), offset, len)?;
                Ok(Box::new(file))
            }
            Some(RarcNodeKind::Directory(_, _)) => Err(VfsError::IsADirectory),
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
            Some(RarcNodeKind::Directory(_, dir)) => {
                let mut entries = Vec::new();
                for node in view.children(dir) {
                    let name = view.get_string(node.name_offset())?;
                    if name == "." || name == ".." {
                        continue;
                    }
                    entries.push(name.to_string());
                }
                Ok(entries)
            }
            Some(RarcNodeKind::File(_, _)) => Err(VfsError::NotADirectory),
            None => Err(VfsError::NotFound),
        }
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        let metadata = self.file.metadata()?;
        let view = self.view()?;
        match view.find(path) {
            Some(RarcNodeKind::File(_, node)) => Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: node.data_length() as u64,
                mtime: metadata.mtime,
            }),
            Some(RarcNodeKind::Directory(_, _)) => {
                Ok(VfsMetadata { file_type: VfsFileType::Directory, len: 0, mtime: metadata.mtime })
            }
            None => Err(VfsError::NotFound),
        }
    }
}
