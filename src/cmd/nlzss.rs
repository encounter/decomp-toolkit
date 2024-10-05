use std::fs;

use anyhow::{anyhow, Context, Result};
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{file::process_rsp, nlzss, path::native_path, IntoCow, ToCow},
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing NLZSS-compressed files.
#[argp(subcommand, name = "nlzss")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Decompress(DecompressArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Decompresses NLZSS-compressed files.
#[argp(subcommand, name = "decompress")]
pub struct DecompressArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// NLZSS-compressed file(s)
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// Output file (or directory, if multiple files are specified).
    /// If not specified, decompresses in-place.
    output: Option<Utf8NativePathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Decompress(args) => decompress(args),
    }
}

fn decompress(args: DecompressArgs) -> Result<()> {
    let files = process_rsp(&args.files)?;
    let single_file = files.len() == 1;
    for path in files {
        let mut file = open_file(&path, false)?;
        let data = nlzss::decompress(file.as_mut())
            .map_err(|e| anyhow!("Failed to decompress '{}' with NLZSS: {}", path, e))?;
        let out_path = if let Some(output) = &args.output {
            if single_file {
                output.as_path().to_cow()
            } else {
                output.join(path.file_name().unwrap()).into_cow()
            }
        } else {
            path.as_path().to_cow()
        };
        fs::write(out_path.as_ref(), data)
            .with_context(|| format!("Failed to write '{}'", out_path))?;
    }
    Ok(())
}
