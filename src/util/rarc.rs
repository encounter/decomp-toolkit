// Source: https://github.com/Julgodis/picori/blob/650da9f4fe6050b39b80d5360416591c748058d5/src/rarc.rs
// License: MIT
// Modified to use `std::io::Cursor<&[u8]>` and `byteorder`
use std::{
    collections::HashMap,
    fmt::Display,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

use crate::util::file::read_c_string;

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

impl std::hash::Hash for NamedHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) { self.hash.hash(state); }
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

impl RarcReader {
    /// Creates a new RARC reader.
    pub fn new<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let base = reader.stream_position()?;

        let magic = reader.read_u32::<LittleEndian>()?;
        let _file_length = reader.read_u32::<BigEndian>()?;
        let header_length = reader.read_u32::<BigEndian>()?;
        let file_offset = reader.read_u32::<BigEndian>()?;
        let _file_length = reader.read_u32::<BigEndian>()?;
        let _ = reader.read_u32::<BigEndian>()?;
        let _ = reader.read_u32::<BigEndian>()?;
        let _ = reader.read_u32::<BigEndian>()?;
        let node_count = reader.read_u32::<BigEndian>()?;
        let node_offset = reader.read_u32::<BigEndian>()?;
        let directory_count = reader.read_u32::<BigEndian>()?;
        let directory_offset = reader.read_u32::<BigEndian>()?;
        let string_table_length = reader.read_u32::<BigEndian>()?;
        let string_table_offset = reader.read_u32::<BigEndian>()?;
        let _file_count = reader.read_u16::<BigEndian>()?;
        let _ = reader.read_u16::<BigEndian>()?;
        let _ = reader.read_u32::<BigEndian>()?;

        ensure!(magic == 0x43524152, "invalid RARC magic");
        ensure!(node_count < 0x10000, "invalid node count");
        ensure!(directory_count < 0x10000, "invalid directory count");

        let base = base + header_length as u64;
        let directory_base = base + directory_offset as u64;
        let data_base = base + file_offset as u64;
        let mut directories = Vec::with_capacity(directory_count as usize);
        for i in 0..directory_count {
            reader.seek(SeekFrom::Start(directory_base + 20 * i as u64))?;
            let index = reader.read_u16::<BigEndian>()?;
            let name_hash = reader.read_u16::<BigEndian>()?;
            let _ = reader.read_u16::<BigEndian>()?; // 0x200 for folders, 0x1100 for files
            let name_offset = reader.read_u16::<BigEndian>()?;
            let data_offset = reader.read_u32::<BigEndian>()?;
            let data_length = reader.read_u32::<BigEndian>()?;
            let _ = reader.read_u32::<BigEndian>()?;

            let name = {
                let offset = string_table_offset as u64;
                let offset = offset + name_offset as u64;
                ensure!((name_offset as u32) < string_table_length, "invalid string table offset");
                read_c_string(reader, base + offset)
            }?;

            if index == 0xFFFF {
                if name == "." {
                    directories.push(RarcDirectory::CurrentFolder);
                } else if name == ".." {
                    directories.push(RarcDirectory::ParentFolder);
                } else {
                    directories
                        .push(RarcDirectory::Folder { name: NamedHash { name, hash: name_hash } });
                }
            } else {
                directories.push(RarcDirectory::File {
                    name: NamedHash { name, hash: name_hash },
                    offset: data_base + data_offset as u64,
                    size: data_length,
                });
            }
        }

        let node_base = base + node_offset as u64;
        let mut root_node: Option<NamedHash> = None;
        let mut nodes = HashMap::with_capacity(node_count as usize);
        for i in 0..node_count {
            reader.seek(SeekFrom::Start(node_base + 16 * i as u64))?;
            let _identifier = reader.read_u32::<BigEndian>()?;
            let name_offset = reader.read_u32::<BigEndian>()?;
            let name_hash = reader.read_u16::<BigEndian>()?;
            let count = reader.read_u16::<BigEndian>()? as u32;
            let index = reader.read_u32::<BigEndian>()?;

            ensure!(index < directory_count, "first directory index out of bounds");

            let last_index = index.checked_add(count);
            ensure!(
                last_index.is_some() && last_index.unwrap() <= directory_count,
                "last directory index out of bounds"
            );

            let name = {
                let offset = string_table_offset as u64;
                let offset = offset + name_offset as u64;
                ensure!(name_offset < string_table_length, "invalid string table offset");
                read_c_string(reader, base + offset)
            }?;

            // FIXME: this assumes that the root node is the first node in the list
            if root_node.is_none() {
                root_node = Some(NamedHash { name: name.clone(), hash: name_hash });
            }

            let name = NamedHash { name, hash: name_hash };
            nodes.insert(name.clone(), RarcNode { index, count });
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
    pub fn find_file<P: AsRef<Path>>(&self, path: P) -> Result<Option<(u64, u32)>> {
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
