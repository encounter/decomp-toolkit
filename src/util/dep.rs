use std::io::Write;

use itertools::Itertools;
use typed_path::{Utf8NativePath, Utf8NativePathBuf, Utf8UnixPathBuf};

pub struct DepFile {
    pub name: Utf8UnixPathBuf,
    pub dependencies: Vec<Utf8UnixPathBuf>,
}

fn normalize_path(path: Utf8NativePathBuf) -> Utf8UnixPathBuf {
    if let Some((a, _)) = path.as_str().split_once(':') {
        Utf8NativePath::new(a).with_unix_encoding()
    } else {
        path.with_unix_encoding()
    }
}

impl DepFile {
    pub fn new(name: Utf8NativePathBuf) -> Self {
        Self { name: name.with_unix_encoding(), dependencies: vec![] }
    }

    pub fn push(&mut self, dependency: Utf8NativePathBuf) {
        self.dependencies.push(normalize_path(dependency));
    }

    pub fn extend(&mut self, dependencies: Vec<Utf8NativePathBuf>) {
        self.dependencies.extend(dependencies.into_iter().map(normalize_path));
    }

    pub fn write<W>(&self, w: &mut W) -> std::io::Result<()>
    where W: Write + ?Sized {
        write!(w, "{}:", self.name)?;
        for dep in self.dependencies.iter().unique() {
            write!(w, " \\\n  {}", dep.as_str().replace(' ', "\\ "))?;
        }
        Ok(())
    }
}
