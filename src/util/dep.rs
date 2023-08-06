use std::{io::Write, path::PathBuf};

pub struct DepFile {
    pub name: PathBuf,
    pub dependencies: Vec<PathBuf>,
}

impl DepFile {
    pub fn new(name: PathBuf) -> Self { Self { name, dependencies: vec![] } }

    pub fn push(&mut self, dependency: PathBuf) { self.dependencies.push(dependency); }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        write!(w, "{}:", self.name.display())?;
        for dep in &self.dependencies {
            write!(w, " \\\n  {}", dep.display())?;
        }
        Ok(())
    }
}
