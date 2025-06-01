use std::fs;

use anyhow::{Context, Result};
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{
        file::process_rsp,
        ncompress::{compress_yay0, decompress_yay0},
        path::native_path,
        IntoCow, ToCow,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing YAY0-compressed files.
#[argp(subcommand, name = "yay0")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Compress(CompressArgs),
    Decompress(DecompressArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Compresses files using YAY0.
#[argp(subcommand, name = "compress")]
pub struct CompressArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// Files to compress
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// Output file (or directory, if multiple files are specified).
    /// If not specified, compresses in-place.
    output: Option<Utf8NativePathBuf>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Decompresses YAY0-compressed files.
#[argp(subcommand, name = "decompress")]
pub struct DecompressArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// YAY0-compressed files
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// Output file (or directory, if multiple files are specified).
    /// If not specified, decompresses in-place.
    output: Option<Utf8NativePathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Compress(args) => compress(args),
        SubCommand::Decompress(args) => decompress(args),
    }
}

fn compress(args: CompressArgs) -> Result<()> {
    let files = process_rsp(&args.files)?;
    let single_file = files.len() == 1;
    for path in files {
        let data = {
            let mut file = open_file(&path, false)?;
            compress_yay0(file.map()?)
        };
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
            .with_context(|| format!("Failed to write '{out_path}'"))?;
    }
    Ok(())
}

fn decompress(args: DecompressArgs) -> Result<()> {
    let files = process_rsp(&args.files)?;
    let single_file = files.len() == 1;
    for path in files {
        let data = {
            let mut file = open_file(&path, true)?;
            decompress_yay0(file.map()?)
                .with_context(|| format!("Failed to decompress '{path}' using Yay0"))?
        };
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
            .with_context(|| format!("Failed to write '{out_path}'"))?;
    }
    Ok(())
}
