use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use argp::FromArgs;
use memchr::memmem;
use memmap2::MmapOptions;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Sets the MetroidBuildInfo tag value in a given binary.
#[argp(subcommand, name = "metroidbuildinfo")]
pub struct Args {
    #[argp(positional)]
    /// path to source binary
    binary: PathBuf,
    #[argp(positional)]
    /// path to build info string
    build_info: PathBuf,
}

const BUILD_STRING_MAX: usize = 35;
const BUILD_STRING_TAG: &str = "!#$MetroidBuildInfo!#$";

pub fn run(args: Args) -> Result<()> {
    let build_string = std::fs::read_to_string(&args.build_info).with_context(|| {
        format!("Failed to read build info string from '{}'", args.build_info.display())
    })?;
    let build_string_trim = build_string.trim_end();
    let build_string_bytes = build_string_trim.as_bytes();
    ensure!(
        build_string_bytes.len() <= BUILD_STRING_MAX,
        "Build string '{build_string_trim}' is greater than maximum size of {BUILD_STRING_MAX}"
    );

    let binary_file =
        std::fs::File::options().read(true).write(true).open(&args.binary).with_context(|| {
            format!("Failed to open binary for writing: '{}'", args.binary.display())
        })?;
    let mut map = unsafe { MmapOptions::new().map_mut(&binary_file) }
        .with_context(|| format!("Failed to mmap binary: '{}'", args.binary.display()))?;
    let start = match memmem::find(&map, BUILD_STRING_TAG.as_bytes()) {
        Some(idx) => idx + BUILD_STRING_TAG.as_bytes().len(),
        None => bail!("Failed to find build string tag in binary"),
    };
    let end = start + build_string_bytes.len();
    map[start..end].copy_from_slice(build_string_bytes);
    map[end] = 0;
    Ok(())
}
