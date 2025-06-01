use std::{borrow::Cow, ffi::CStr};

use typed_path::Utf8UnixPath;
use zerocopy::{big_endian::*, FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{static_assert, vfs::next_non_empty};

pub const RARC_MAGIC: [u8; 4] = *b"RARC";

#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct RarcHeader {
    /// Magic identifier. (Always "RARC")
    magic: [u8; 4],
    /// Length of the RARC file.
    file_len: U32,
    /// Length of the header. (Always 32)
    header_len: U32,
    /// Start of the file data, relative to the end of the file header.
    data_offset: U32,
    /// Length of the file data.
    data_len: U32,
    _unk1: U32,
    _unk2: U32,
    _unk3: U32,
}

static_assert!(size_of::<RarcHeader>() == 0x20);

impl RarcHeader {
    /// Length of the RARC file.
    pub fn file_len(&self) -> u32 { self.file_len.get() }

    /// Length of the header.
    pub fn header_len(&self) -> u32 { self.header_len.get() }

    /// Start of the file data, relative to the end of the file header.
    pub fn data_offset(&self) -> u32 { self.data_offset.get() }

    /// Length of the file data.
    pub fn data_len(&self) -> u32 { self.data_len.get() }
}

#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
struct RarcInfo {
    /// Number of directories in the directory table.
    directory_count: U32,
    /// Offset to the start of the directory table, relative to the end of the file header.
    directory_offset: U32,
    /// Number of nodes in the node table.
    node_count: U32,
    /// Offset to the start of the node table, relative to the end of the file header.
    node_offset: U32,
    /// Length of the string table.
    string_table_len: U32,
    /// Offset to the start of the string table, relative to the end of the file header.
    string_table_offset: U32,
    /// Number of files in the node table.
    _file_count: U16,
    _unk4: U16,
    _unk5: U32,
}

static_assert!(size_of::<RarcInfo>() == 0x20);

#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct RarcNode {
    /// Index of the node. (0xFFFF for directories)
    index: U16,
    /// Hash of the node name.
    name_hash: U16,
    /// Unknown. (0x200 for folders, 0x1100 for files)
    _unk0: U16,
    /// Offset in the string table to the node name.
    name_offset: U16,
    /// Files: Offset in the data to the file data.
    /// Directories: Index of the directory in the directory table.
    data_offset: U32,
    /// Files: Length of the data.
    /// Directories: Unknown. Always 16.
    data_length: U32,
    _unk1: U32,
}

static_assert!(size_of::<RarcNode>() == 0x14);

impl RarcNode {
    /// Whether the node is a file.
    pub fn is_file(&self) -> bool { self.index.get() != 0xFFFF }

    /// Whether the node is a directory.
    pub fn is_dir(&self) -> bool { self.index.get() == 0xFFFF }

    /// Offset in the string table to the node name.
    pub fn name_offset(&self) -> u32 { self.name_offset.get() as u32 }

    /// Files: Offset in the data to the file data.
    /// Directories: Index of the directory in the directory table.
    pub fn data_offset(&self) -> u32 { self.data_offset.get() }

    /// Files: Length of the data.
    /// Directories: Unknown. Always 16.
    pub fn data_length(&self) -> u32 { self.data_length.get() }
}

#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct RarcDirectory {
    /// Identifier of the directory.
    identifier: [u8; 4],
    /// Offset in the string table to the directory name.
    name_offset: U32,
    /// Hash of the directory name.
    name_hash: U16,
    /// Number of nodes in the directory.
    count: U16,
    /// Index of the first node in the directory.
    index: U32,
}

static_assert!(size_of::<RarcDirectory>() == 0x10);

impl RarcDirectory {
    /// Offset in the string table to the directory name.
    pub fn name_offset(&self) -> u32 { self.name_offset.get() }

    /// Index of the first node in the directory.
    pub fn node_index(&self) -> u32 { self.index.get() }

    /// Number of nodes in the directory.
    pub fn node_count(&self) -> u16 { self.count.get() }
}

/// A view into a RARC archive.
pub struct RarcView<'a> {
    /// The RARC archive header.
    pub header: &'a RarcHeader,
    /// The directories in the RARC archive.
    pub directories: &'a [RarcDirectory],
    /// The nodes in the RARC archive.
    pub nodes: &'a [RarcNode],
    /// The string table containing all file and directory names.
    pub string_table: &'a [u8],
    /// The file data.
    pub data: &'a [u8],
}

impl<'a> RarcView<'a> {
    /// Create a new RARC view from a buffer.
    pub fn new(buf: &'a [u8]) -> Result<Self, &'static str> {
        let Ok((header, remaining)) = RarcHeader::ref_from_prefix(buf) else {
            return Err("Buffer not large enough for RARC header");
        };
        if header.magic != RARC_MAGIC {
            return Err("RARC magic mismatch");
        }
        if header.header_len.get() as usize != size_of::<RarcHeader>() {
            return Err("RARC header size mismatch");
        }

        // All offsets are relative to the _end_ of the header, so we can
        // just trim the header from the buffer and use the offsets as is.
        let Ok((info, _)) = RarcInfo::ref_from_prefix(remaining) else {
            return Err("Buffer not large enough for RARC info");
        };

        let directory_table_offset = info.directory_offset.get() as usize;
        let directory_table_size = info.directory_count.get() as usize * size_of::<RarcDirectory>();
        let directories_buf = remaining
            .get(directory_table_offset..directory_table_offset + directory_table_size)
            .ok_or("RARC directory table out of bounds")?;
        let directories = <[RarcDirectory]>::ref_from_bytes(directories_buf)
            .map_err(|_| "RARC directory table not aligned")?;
        if directories.is_empty() || directories[0].identifier != *b"ROOT" {
            return Err("RARC root directory not found");
        }

        let node_table_offset = info.node_offset.get() as usize;
        let node_table_size = info.node_count.get() as usize * size_of::<RarcNode>();
        let nodes_buf = remaining
            .get(node_table_offset..node_table_offset + node_table_size)
            .ok_or("RARC node table out of bounds")?;
        let nodes =
            <[RarcNode]>::ref_from_bytes(nodes_buf).map_err(|_| "RARC node table not aligned")?;

        let string_table_offset = info.string_table_offset.get() as usize;
        let string_table_size = info.string_table_len.get() as usize;
        let string_table = remaining
            .get(string_table_offset..string_table_offset + string_table_size)
            .ok_or("RARC string table out of bounds")?;

        let data_offset = header.data_offset.get() as usize;
        let data_size = header.data_len.get() as usize;
        let data =
            buf.get(data_offset..data_offset + data_size).ok_or("RARC file data out of bounds")?;

        Ok(Self { header, directories, nodes, string_table, data })
    }

    /// Get a string from the string table at the given offset.
    pub fn get_string(&self, offset: u32) -> Result<Cow<str>, String> {
        let name_buf = self.string_table.get(offset as usize..).ok_or_else(|| {
            format!(
                "RARC: name offset {} out of bounds (string table size: {})",
                offset,
                self.string_table.len()
            )
        })?;
        let c_string = CStr::from_bytes_until_nul(name_buf)
            .map_err(|_| format!("RARC: name at offset {offset} not null-terminated"))?;
        Ok(c_string.to_string_lossy())
    }

    /// Get the data for a file node.
    pub fn get_data(&self, node: RarcNode) -> Result<&[u8], &'static str> {
        if node.is_dir() {
            return Err("Cannot get data for a directory node");
        }
        let offset = node.data_offset.get() as usize;
        let size = node.data_length.get() as usize;
        self.data.get(offset..offset + size).ok_or("RARC file data out of bounds")
    }

    /// Finds a particular file or directory by path.
    pub fn find(&self, path: &Utf8UnixPath) -> Option<RarcNodeKind> {
        let mut split = path.as_str().split('/');
        let mut current = next_non_empty(&mut split);

        let mut dir_idx = 0;
        let mut dir = self.directories[dir_idx];
        // Allow matching the root directory by name optionally
        if let Ok(root_name) = self.get_string(dir.name_offset()) {
            if root_name.eq_ignore_ascii_case(current) {
                current = next_non_empty(&mut split);
            }
        }
        if current.is_empty() {
            return Some(RarcNodeKind::Directory(dir_idx, dir));
        }

        let mut idx = dir.index.get() as usize;
        while idx < dir.index.get() as usize + dir.count.get() as usize {
            let node = self.nodes.get(idx).copied()?;
            let Ok(name) = self.get_string(node.name_offset()) else {
                idx += 1;
                continue;
            };
            if name.eq_ignore_ascii_case(current) {
                current = next_non_empty(&mut split);
                if node.is_dir() {
                    dir_idx = node.data_offset.get() as usize;
                    dir = self.directories.get(dir_idx).cloned()?;
                    idx = dir.index.get() as usize;
                    if current.is_empty() {
                        return Some(RarcNodeKind::Directory(dir_idx, dir));
                    } else {
                        continue;
                    }
                } else {
                    return Some(RarcNodeKind::File(idx, node));
                }
            }
            idx += 1;
        }

        None
    }

    /// Get the children of a directory.
    pub fn children(&self, dir: RarcDirectory) -> &[RarcNode] {
        let start = dir.node_index() as usize;
        let end = start + dir.node_count() as usize;
        self.nodes.get(start..end).unwrap_or(&[])
    }
}

#[derive(Debug)]
pub enum RarcNodeKind {
    File(usize, RarcNode),
    Directory(usize, RarcDirectory),
}
