use std::{io::Write, path::PathBuf};

use path_slash::PathBufExt;

pub struct DepFile {
    pub name: PathBuf,
    pub dependencies: Vec<PathBuf>,
}

impl DepFile {
    pub fn new(name: PathBuf) -> Self { Self { name, dependencies: vec![] } }

    pub fn push(&mut self, dependency: PathBuf) { self.dependencies.push(dependency); }

    pub fn extend(&mut self, dependencies: Vec<PathBuf>) { self.dependencies.extend(dependencies); }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        write!(w, "{}:", self.name.to_slash_lossy())?;
        for dep in &self.dependencies {
            write!(w, " \\\n  {}", dep.to_slash_lossy())?;
        }
        Ok(())
    }
}
