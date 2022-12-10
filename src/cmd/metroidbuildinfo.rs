use anyhow::{Context, Error, Result};
use argh::FromArgs;
use memchr::memmem;
use memmap2::MmapOptions;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Sets the MetroidBuildInfo tag value in a given binary.
#[argh(subcommand, name = "metroidbuildinfo")]
pub struct Args {
    #[argh(positional)]
    /// path to source binary
    binary: String,
    #[argh(positional)]
    /// path to build info string
    build_info: String,
}

const BUILD_STRING_MAX: usize = 35;
const BUILD_STRING_TAG: &str = "!#$MetroidBuildInfo!#$";

pub fn run(args: Args) -> Result<()> {
    let build_string = std::fs::read_to_string(&args.build_info)
        .with_context(|| format!("Failed to read build info string from '{}'", args.build_info))?;
    let build_string_trim = build_string.trim_end();
    let build_string_bytes = build_string_trim.as_bytes();
    if build_string_bytes.len() > BUILD_STRING_MAX {
        return Err(Error::msg(format!(
            "Build string '{build_string_trim}' is greater than maximum size of {BUILD_STRING_MAX}"
        )));
    }

    let binary_file = std::fs::File::options()
        .read(true)
        .write(true)
        .open(&args.binary)
        .with_context(|| format!("Failed to open binary for writing: '{}'", args.binary))?;
    let mut map = unsafe { MmapOptions::new().map_mut(&binary_file) }
        .with_context(|| format!("Failed to mmap binary: '{}'", args.binary))?;
    let start = match memmem::find(&map, BUILD_STRING_TAG.as_bytes()) {
        Some(idx) => idx + BUILD_STRING_TAG.as_bytes().len(),
        None => return Err(Error::msg("Failed to find build string tag in binary")),
    };
    let end = start + build_string_bytes.len();
    map[start..end].copy_from_slice(build_string_bytes);
    map[end] = 0;
    Ok(())
}
