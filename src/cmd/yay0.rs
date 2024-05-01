use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use argp::FromArgs;

use crate::util::{
    file::{map_file_basic, process_rsp},
    ncompress::{compress_yay0, decompress_yay0},
    IntoCow, ToCow,
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
    #[argp(positional)]
    /// Files to compress
    files: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// Output file (or directory, if multiple files are specified).
    /// If not specified, compresses in-place.
    output: Option<PathBuf>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Decompresses YAY0-compressed files.
#[argp(subcommand, name = "decompress")]
pub struct DecompressArgs {
    #[argp(positional)]
    /// YAY0-compressed files
    files: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// Output file (or directory, if multiple files are specified).
    /// If not specified, decompresses in-place.
    output: Option<PathBuf>,
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
            let file = map_file_basic(&path)?;
            compress_yay0(file.as_slice())
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
            .with_context(|| format!("Failed to write '{}'", out_path.display()))?;
    }
    Ok(())
}

fn decompress(args: DecompressArgs) -> Result<()> {
    let files = process_rsp(&args.files)?;
    let single_file = files.len() == 1;
    for path in files {
        let data = {
            let file = map_file_basic(&path)?;
            decompress_yay0(file.as_slice())
                .with_context(|| format!("Failed to decompress '{}' using Yay0", path.display()))?
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
            .with_context(|| format!("Failed to write '{}'", out_path.display()))?;
    }
    Ok(())
}
