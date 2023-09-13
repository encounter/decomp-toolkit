use std::{
    io::Write,
    path::{Path, PathBuf},
};

use itertools::Itertools;
use path_slash::PathBufExt;

use crate::util::file::split_path;

pub struct DepFile {
    pub name: PathBuf,
    pub dependencies: Vec<PathBuf>,
}

impl DepFile {
    pub fn new(name: PathBuf) -> Self { Self { name, dependencies: vec![] } }

    pub fn push<P: AsRef<Path>>(&mut self, dependency: P) {
        let path = split_path(dependency.as_ref())
            .map(|(p, _)| p)
            .unwrap_or_else(|_| dependency.as_ref().to_path_buf());
        self.dependencies.push(path);
    }

    pub fn extend(&mut self, dependencies: Vec<PathBuf>) {
        self.dependencies.extend(dependencies.iter().map(|dependency| {
            split_path(dependency).map(|(p, _)| p).unwrap_or_else(|_| dependency.clone())
        }));
    }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        write!(w, "{}:", self.name.to_slash_lossy())?;
        for dep in self.dependencies.iter().unique() {
            write!(w, " \\\n  {}", dep.to_slash_lossy().replace(' ', "\\ "))?;
        }
        Ok(())
    }
}
