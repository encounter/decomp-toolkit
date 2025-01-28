use std::{borrow::Cow, ffi::CStr, mem::size_of};

use anyhow::Result;
use typed_path::Utf8UnixPath;
use zerocopy::{big_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{static_assert, vfs::next_non_empty};

pub const U8_MAGIC: [u8; 4] = [0x55, 0xAA, 0x38, 0x2D];

/// U8 archive header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct U8Header {
    magic: [u8; 4],
    node_table_offset: U32,
    node_table_size: U32,
    data_offset: U32,
    _pad: [u8; 16],
}

static_assert!(size_of::<U8Header>() == 32);

/// File system node kind.
#[derive(Clone, Debug, PartialEq)]
pub enum U8NodeKind {
    /// Node is a file.
    File,
    /// Node is a directory.
    Directory,
    /// Invalid node kind. (Should not normally occur)
    Invalid,
}

/// An individual file system node.
#[derive(Copy, Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct U8Node {
    kind: u8,
    // u24 big-endian
    name_offset: [u8; 3],
    offset: U32,
    length: U32,
}

static_assert!(size_of::<U8Node>() == 12);

impl U8Node {
    /// File system node kind.
    pub fn kind(&self) -> U8NodeKind {
        match self.kind {
            0 => U8NodeKind::File,
            1 => U8NodeKind::Directory,
            _ => U8NodeKind::Invalid,
        }
    }

    /// Whether the node is a file.
    pub fn is_file(&self) -> bool { self.kind == 0 }

    /// Whether the node is a directory.
    pub fn is_dir(&self) -> bool { self.kind == 1 }

    /// Offset in the string table to the filename.
    pub fn name_offset(&self) -> u32 {
        u32::from_be_bytes([0, self.name_offset[0], self.name_offset[1], self.name_offset[2]])
    }

    /// For files, this is the data offset of the file data (relative to header.data_offset).
    ///
    /// For directories, this is the parent node index in the node table.
    pub fn offset(&self) -> u32 { self.offset.get() }

    /// For files, this is the byte size of the file.
    ///
    /// For directories, this is the child end index in the node table.
    ///
    /// Number of child files and directories recursively is `length - offset`.
    pub fn length(&self) -> u32 { self.length.get() }
}

/// A view into a U8 archive.
pub struct U8View<'a> {
    /// The U8 archive header.
    pub header: &'a U8Header,
    /// The nodes in the U8 archive.
    pub nodes: &'a [U8Node],
    /// The string table containing all file and directory names.
    pub string_table: &'a [u8],
}

impl<'a> U8View<'a> {
    /// Create a new U8 view from a buffer.
    pub fn new(buf: &'a [u8]) -> Result<Self, &'static str> {
        let Ok((header, _)) = U8Header::ref_from_prefix(buf) else {
            return Err("Buffer not large enough for U8 header");
        };
        if header.magic != U8_MAGIC {
            return Err("U8 magic mismatch");
        }
        let node_table_offset = header.node_table_offset.get() as usize;
        let nodes_buf = buf
            .get(node_table_offset..node_table_offset + header.node_table_size.get() as usize)
            .ok_or("U8 node table out of bounds")?;
        let (root_node, _) =
            U8Node::ref_from_prefix(nodes_buf).map_err(|_| "U8 root node not aligned")?;
        if root_node.kind() != U8NodeKind::Directory {
            return Err("U8 root node is not a directory");
        }
        if root_node.offset() != 0 {
            return Err("U8 root node offset is not zero");
        }
        let node_count = root_node.length() as usize;
        if node_count * size_of::<U8Node>() > header.node_table_size.get() as usize {
            return Err("U8 node table size mismatch");
        }
        let (nodes_buf, string_table) = nodes_buf.split_at(node_count * size_of::<U8Node>());
        let nodes =
            <[U8Node]>::ref_from_bytes(nodes_buf).map_err(|_| "U8 node table not aligned")?;
        Ok(Self { header, nodes, string_table })
    }

    /// Iterate over the nodes in the U8 archive.
    pub fn iter(&self) -> U8Iter { U8Iter { inner: self, idx: 1 } }

    /// Get the name of a node.
    pub fn get_name(&self, node: U8Node) -> Result<Cow<str>, String> {
        let name_buf = self.string_table.get(node.name_offset() as usize..).ok_or_else(|| {
            format!(
                "U8: name offset {} out of bounds (string table size: {})",
                node.name_offset(),
                self.string_table.len()
            )
        })?;
        let c_string = CStr::from_bytes_until_nul(name_buf).map_err(|_| {
            format!("U8: name at offset {} not null-terminated", node.name_offset())
        })?;
        Ok(c_string.to_string_lossy())
    }

    /// Finds a particular file or directory by path.
    pub fn find(&self, path: &Utf8UnixPath) -> Option<(usize, U8Node)> {
        let mut split = path.as_str().split('/');
        let mut current = next_non_empty(&mut split);
        if current.is_empty() {
            return Some((0, self.nodes[0]));
        }

        let mut idx = 1;
        let mut stop_at = None;
        while let Some(node) = self.nodes.get(idx).copied() {
            if self.get_name(node).is_ok_and(|name| name.eq_ignore_ascii_case(current)) {
                current = next_non_empty(&mut split);
                if current.is_empty() {
                    return Some((idx, node));
                }
                if node.is_dir() {
                    // Descend into directory
                    idx += 1;
                    stop_at = Some(node.length() as usize + idx);
                } else {
                    // Not a directory
                    break;
                }
            } else if node.is_dir() {
                // Skip directory
                idx = node.length() as usize;
            } else {
                // Skip file
                idx += 1;
            }
            if let Some(stop) = stop_at {
                if idx >= stop {
                    break;
                }
            }
        }
        None
    }
}

/// Iterator over the nodes in a U8 archive.
pub struct U8Iter<'a> {
    inner: &'a U8View<'a>,
    idx: usize,
}

impl<'a> Iterator for U8Iter<'a> {
    type Item = (usize, U8Node, Result<Cow<'a, str>, String>);

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.idx;
        let node = self.inner.nodes.get(idx).copied()?;
        let name = self.inner.get_name(node);
        self.idx += 1;
        Some((idx, node, name))
    }
}
