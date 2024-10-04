use std::{
    io::Write,
    path::{Path, PathBuf},
};

use itertools::Itertools;

pub struct DepFile {
    pub name: String,
    pub dependencies: Vec<String>,
}

fn normalize_path(path: &Path) -> String {
    let path = path.to_string_lossy().replace('\\', "/");
    path.split_once(':').map(|(p, _)| p.to_string()).unwrap_or(path)
}

impl DepFile {
    pub fn new(name: PathBuf) -> Self {
        Self { name: name.to_string_lossy().into_owned(), dependencies: vec![] }
    }

    pub fn push<P>(&mut self, dependency: P)
    where P: AsRef<Path> {
        let path = dependency.as_ref().to_string_lossy().replace('\\', "/");
        let path = path.split_once(':').map(|(p, _)| p.to_string()).unwrap_or(path);
        self.dependencies.push(path);
    }

    pub fn extend(&mut self, dependencies: Vec<PathBuf>) {
        self.dependencies.extend(dependencies.iter().map(|dependency| normalize_path(dependency)));
    }

    pub fn write<W>(&self, w: &mut W) -> std::io::Result<()>
    where W: Write + ?Sized {
        write!(w, "{}:", self.name)?;
        for dep in self.dependencies.iter().unique() {
            write!(w, " \\\n  {}", dep.replace(' ', "\\ "))?;
        }
        Ok(())
    }
}
