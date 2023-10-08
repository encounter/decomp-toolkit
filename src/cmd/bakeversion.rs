use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use argp::FromArgs;
use memchr::memmem;
use memmap2::MmapOptions;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Sets the MetroidBuildInfo tag value in a given binary.
#[argp(subcommand, name = "bakeversion")]
pub struct Args {
    #[argp(positional)]
    /// path to source binary
    binary: PathBuf,
    #[argp(positional)]
    /// build tag marker to search for
    build_tag: String,
    #[argp(positional)]
    /// path to build info string
    build_info: PathBuf,
    #[argp(option, short = 'm', default="35")]
    /// the max length of the version string, excluding build_tag (default: 35)
    max_len: usize,
}

pub fn run(args: Args) -> Result<()> {
    let build_string = std::fs::read_to_string(&args.build_info).with_context(|| {
        format!("Failed to read build info string from '{}'", args.build_info.display())
    })?;
    let build_string_trim = build_string.trim_end();
    let build_string_bytes = build_string_trim.as_bytes();

    let max_len = args.max_len;
    ensure!(
        build_string_bytes.len() <= max_len,
        "Build string '{build_string_trim}' is greater than maximum size of {max_len}"
    );

    let binary_file =
        std::fs::File::options().read(true).write(true).open(&args.binary).with_context(|| {
            format!("Failed to open binary for writing: '{}'", args.binary.display())
        })?;
    let mut map = unsafe { MmapOptions::new().map_mut(&binary_file) }
        .with_context(|| format!("Failed to mmap binary: '{}'", args.binary.display()))?;
    let start = match memmem::find(&map, args.build_tag.as_bytes()) {
        Some(idx) => idx + args.build_tag.as_bytes().len(),
        None => bail!("Failed to find build string tag in binary"),
    };
    let end = start + build_string_bytes.len();
    map[start..end].copy_from_slice(build_string_bytes);
    map[end] = 0;
    Ok(())
}
