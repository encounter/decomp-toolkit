// Source: https://github.com/Julgodis/picori/blob/650da9f4fe6050b39b80d5360416591c748058d5/src/rarc.rs
// License: MIT
// Modified to use `std::io::Cursor<&[u8]>` and project's FromReader trait
use std::{
    collections::HashMap,
    fmt::Display,
    hash::{Hash, Hasher},
    io,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Result};

use crate::util::{
    file::read_c_string,
    reader::{struct_size, Endian, FromReader},
};

#[derive(Debug, Clone)]
pub struct NamedHash {
    pub name: String,
    pub hash: u16,
}

impl Display for NamedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Hash for NamedHash {
    fn hash<H>(&self, state: &mut H)
    where H: Hasher {
        self.hash.hash(state);
    }
}

impl PartialEq for NamedHash {
    fn eq(&self, other: &Self) -> bool {
        if self.hash == other.hash {
            self.name == other.name
        } else {
            false
        }
    }
}

impl Eq for NamedHash {}

#[derive(Debug, Clone)]
enum RarcDirectory {
    File {
        /// Name of the file.
        name: NamedHash,
        /// Offset of the file in the RARC file. This offset is relative to the start of the RARC file.
        offset: u64,
        /// Size of the file.
        size: u32,
    },
    Folder {
        /// Name of the folder.
        name: NamedHash,
    },
    CurrentFolder,
    ParentFolder,
}

#[derive(Debug, Clone)]
struct RarcNode {
    /// Index of first directory.
    pub index: u32,
    /// Number of directories.
    pub count: u32,
}

pub struct RarcReader {
    directories: Vec<RarcDirectory>,
    nodes: HashMap<NamedHash, RarcNode>,
    root_node: NamedHash,
}

pub const RARC_MAGIC: [u8; 4] = *b"RARC";

struct RarcHeader {
    magic: [u8; 4],
    _file_length: u32,
    header_length: u32,
    file_offset: u32,
    _file_length_2: u32,
    _unk0: u32,
    _unk1: u32,
    _unk2: u32,
    node_count: u32,
    node_offset: u32,
    directory_count: u32,
    directory_offset: u32,
    string_table_length: u32,
    string_table_offset: u32,
    _file_count: u16,
    _unk3: u16,
    _unk4: u32,
}

impl FromReader for RarcHeader {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        4,                // magic
        u32::STATIC_SIZE, // file_length
        u32::STATIC_SIZE, // header_length
        u32::STATIC_SIZE, // file_offset
        u32::STATIC_SIZE, // file_length
        u32::STATIC_SIZE, // unk0
        u32::STATIC_SIZE, // unk1
        u32::STATIC_SIZE, // unk2
        u32::STATIC_SIZE, // node_count
        u32::STATIC_SIZE, // node_offset
        u32::STATIC_SIZE, // directory_count
        u32::STATIC_SIZE, // directory_offset
        u32::STATIC_SIZE, // string_table_length
        u32::STATIC_SIZE, // string_table_offset
        u16::STATIC_SIZE, // file_count
        u16::STATIC_SIZE, // unk3
        u32::STATIC_SIZE, // unk4
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let header = Self {
            magic: <[u8; 4]>::from_reader(reader, e)?,
            _file_length: u32::from_reader(reader, e)?,
            header_length: u32::from_reader(reader, e)?,
            file_offset: u32::from_reader(reader, e)?,
            _file_length_2: u32::from_reader(reader, e)?,
            _unk0: u32::from_reader(reader, e)?,
            _unk1: u32::from_reader(reader, e)?,
            _unk2: u32::from_reader(reader, e)?,
            node_count: u32::from_reader(reader, e)?,
            node_offset: u32::from_reader(reader, e)?,
            directory_count: u32::from_reader(reader, e)?,
            directory_offset: u32::from_reader(reader, e)?,
            string_table_length: u32::from_reader(reader, e)?,
            string_table_offset: u32::from_reader(reader, e)?,
            _file_count: u16::from_reader(reader, e)?,
            _unk3: u16::from_reader(reader, e)?,
            _unk4: u32::from_reader(reader, e)?,
        };
        if header.magic != RARC_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid RARC magic: {:?}", header.magic),
            ));
        }
        if header.node_count >= 0x10000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid node count: {}", header.node_count),
            ));
        }
        if header.directory_count >= 0x10000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid directory count: {}", header.directory_count),
            ));
        }
        Ok(header)
    }
}

struct RarcFileNode {
    index: u16,
    name_hash: u16,
    _unk0: u16, // 0x200 for folders, 0x1100 for files
    name_offset: u16,
    data_offset: u32,
    data_length: u32,
    _unk1: u32,
}

impl FromReader for RarcFileNode {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u16::STATIC_SIZE, // index
        u16::STATIC_SIZE, // name_hash
        u16::STATIC_SIZE, // unk0
        u16::STATIC_SIZE, // name_offset
        u32::STATIC_SIZE, // data_offset
        u32::STATIC_SIZE, // data_length
        u32::STATIC_SIZE, // unk1
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            index: u16::from_reader(reader, e)?,
            name_hash: u16::from_reader(reader, e)?,
            _unk0: u16::from_reader(reader, e)?,
            name_offset: u16::from_reader(reader, e)?,
            data_offset: u32::from_reader(reader, e)?,
            data_length: u32::from_reader(reader, e)?,
            _unk1: u32::from_reader(reader, e)?,
        })
    }
}

struct RarcDirectoryNode {
    _identifier: u32,
    name_offset: u32,
    name_hash: u16,
    count: u16,
    index: u32,
}

impl FromReader for RarcDirectoryNode {
    type Args = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // identifier
        u32::STATIC_SIZE, // name_offset
        u16::STATIC_SIZE, // name_hash
        u16::STATIC_SIZE, // count
        u32::STATIC_SIZE, // index
    ]);

    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        Ok(Self {
            _identifier: u32::from_reader(reader, e)?,
            name_offset: u32::from_reader(reader, e)?,
            name_hash: u16::from_reader(reader, e)?,
            count: u16::from_reader(reader, e)?,
            index: u32::from_reader(reader, e)?,
        })
    }
}

impl RarcReader {
    /// Creates a new RARC reader.
    pub fn new<R>(reader: &mut R) -> Result<Self>
    where R: Read + Seek + ?Sized {
        let base = reader.stream_position()?;
        let header = RarcHeader::from_reader(reader, Endian::Big)?;

        let base = base + header.header_length as u64;
        let directory_base = base + header.directory_offset as u64;
        let data_base = base + header.file_offset as u64;
        let mut directories = Vec::with_capacity(header.directory_count as usize);
        for i in 0..header.directory_count {
            reader.seek(SeekFrom::Start(directory_base + 20 * i as u64))?;
            let node = RarcFileNode::from_reader(reader, Endian::Big)?;

            let name = {
                let offset = header.string_table_offset as u64;
                let offset = offset + node.name_offset as u64;
                ensure!(
                    (node.name_offset as u32) < header.string_table_length,
                    "invalid string table offset"
                );
                read_c_string(reader, base + offset)
            }?;

            if node.index == 0xFFFF {
                if name == "." {
                    directories.push(RarcDirectory::CurrentFolder);
                } else if name == ".." {
                    directories.push(RarcDirectory::ParentFolder);
                } else {
                    directories.push(RarcDirectory::Folder {
                        name: NamedHash { name, hash: node.name_hash },
                    });
                }
            } else {
                directories.push(RarcDirectory::File {
                    name: NamedHash { name, hash: node.name_hash },
                    offset: data_base + node.data_offset as u64,
                    size: node.data_length,
                });
            }
        }

        let node_base = base + header.node_offset as u64;
        let mut root_node: Option<NamedHash> = None;
        let mut nodes = HashMap::with_capacity(header.node_count as usize);
        for i in 0..header.node_count {
            reader.seek(SeekFrom::Start(node_base + 16 * i as u64))?;
            let node = RarcDirectoryNode::from_reader(reader, Endian::Big)?;

            ensure!(node.index < header.directory_count, "first directory index out of bounds");

            let last_index = node.index.checked_add(node.count as u32);
            ensure!(
                last_index.is_some() && last_index.unwrap() <= header.directory_count,
                "last directory index out of bounds"
            );

            let name = {
                let offset = header.string_table_offset as u64;
                let offset = offset + node.name_offset as u64;
                ensure!(
                    node.name_offset < header.string_table_length,
                    "invalid string table offset"
                );
                read_c_string(reader, base + offset)
            }?;

            // FIXME: this assumes that the root node is the first node in the list
            if root_node.is_none() {
                root_node = Some(NamedHash { name: name.clone(), hash: node.name_hash });
            }

            let name = NamedHash { name, hash: node.name_hash };
            nodes.insert(name.clone(), RarcNode { index: node.index, count: node.count as u32 });
        }

        if let Some(root_node) = root_node {
            Ok(Self { directories, nodes, root_node })
        } else {
            Err(anyhow!("no root node"))
        }
    }

    /// Get a iterator over the nodes in the RARC file.
    pub fn nodes(&self) -> Nodes<'_> {
        let root_node = self.root_node.clone();
        Nodes { parent: self, stack: vec![NodeState::Begin(root_node)] }
    }

    /// Find a file in the RARC file.
    pub fn find_file<P>(&self, path: P) -> Result<Option<(u64, u32)>>
    where P: AsRef<Path> {
        let mut cmp_path = PathBuf::new();
        for component in path.as_ref().components() {
            match component {
                Component::Normal(name) => cmp_path.push(name.to_ascii_lowercase()),
                Component::RootDir => {}
                component => bail!("Invalid path component: {:?}", component),
            }
        }

        let mut current_path = PathBuf::new();
        for node in self.nodes() {
            match node {
                Node::DirectoryBegin { name } => {
                    current_path.push(name.name.to_ascii_lowercase());
                }
                Node::DirectoryEnd { name: _ } => {
                    current_path.pop();
                }
                Node::File { name, offset, size } => {
                    if current_path.join(name.name.to_ascii_lowercase()) == cmp_path {
                        return Ok(Some((offset, size)));
                    }
                }
                Node::CurrentDirectory => {}
                Node::ParentDirectory => {}
            }
        }
        Ok(None)
    }
}

/// A node in an RARC file.
pub enum Node {
    /// A directory that has been entered.
    DirectoryBegin { name: NamedHash },
    /// A directory that has been exited.
    DirectoryEnd { name: NamedHash },
    /// A file in the current directory.
    File { name: NamedHash, offset: u64, size: u32 },
    /// The current directory. This is equivalent to ".".
    CurrentDirectory,
    /// The parent directory. This is equivalent to "..".
    ParentDirectory,
}

enum NodeState {
    Begin(NamedHash),
    End(NamedHash),
    File(NamedHash, u32),
}

/// An iterator over the nodes in an RARC file.
pub struct Nodes<'parent> {
    parent: &'parent RarcReader,
    stack: Vec<NodeState>,
}

impl<'parent> Iterator for Nodes<'parent> {
    type Item = Node;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(state) = self.stack.pop() else {
            return None;
        };

        match state {
            NodeState::Begin(name) => {
                self.stack.push(NodeState::File(name.clone(), 0));
                Some(Node::DirectoryBegin { name })
            }
            NodeState::End(name) => Some(Node::DirectoryEnd { name }),
            NodeState::File(name, index) => {
                if let Some(node) = self.parent.nodes.get(&name) {
                    if index + 1 >= node.count {
                        self.stack.push(NodeState::End(name.clone()));
                    } else {
                        self.stack.push(NodeState::File(name.clone(), index + 1));
                    }
                    let directory = &self.parent.directories[(node.index + index) as usize];
                    match directory {
                        RarcDirectory::CurrentFolder => Some(Node::CurrentDirectory),
                        RarcDirectory::ParentFolder => Some(Node::ParentDirectory),
                        RarcDirectory::Folder { name } => {
                            self.stack.push(NodeState::Begin(name.clone()));
                            self.next()
                        }
                        RarcDirectory::File { name, offset, size } => {
                            Some(Node::File { name: name.clone(), offset: *offset, size: *size })
                        }
                    }
                } else {
                    None
                }
            }
        }
    }
}
