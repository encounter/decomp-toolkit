use std::{
    path::{Path, PathBuf},
    str::Utf8Error,
    string::FromUtf8Error,
};

use typed_path::{NativePath, NativePathBuf, Utf8NativePath, Utf8NativePathBuf};

// For argp::FromArgs
pub fn native_path(value: &str) -> Result<Utf8NativePathBuf, String> {
    Ok(Utf8NativePathBuf::from(value))
}

/// Checks if the path is valid UTF-8 and returns it as a [`Utf8NativePath`].
#[inline]
pub fn check_path(path: &Path) -> Result<&Utf8NativePath, Utf8Error> {
    Utf8NativePath::from_bytes_path(NativePath::new(path.as_os_str().as_encoded_bytes()))
}

/// Checks if the path is valid UTF-8 and returns it as a [`Utf8NativePathBuf`].
#[inline]
pub fn check_path_buf(path: PathBuf) -> Result<Utf8NativePathBuf, FromUtf8Error> {
    Utf8NativePathBuf::from_bytes_path_buf(NativePathBuf::from(
        path.into_os_string().into_encoded_bytes(),
    ))
}
