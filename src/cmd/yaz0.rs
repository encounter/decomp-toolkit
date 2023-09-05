use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use argp::FromArgs;

use crate::util::{
    file::{decompress_reader, open_file, process_rsp},
    IntoCow, ToCow,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing YAZ0-compressed files.
#[argp(subcommand, name = "yaz0")]
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
/// Decompresses YAZ0-compressed files.
#[argp(subcommand, name = "decompress")]
pub struct DecompressArgs {
    #[argp(positional)]
    /// YAZ0-compressed files
    files: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// Output directory. If not specified, decompresses in-place.
    output: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Decompress(args) => decompress(args),
    }
}

fn decompress(args: DecompressArgs) -> Result<()> {
    for path in process_rsp(&args.files)? {
        let data = decompress_reader(&mut open_file(&path)?)?;
        let out_path = if let Some(output) = &args.output {
            output.join(path.file_name().unwrap()).into_cow()
        } else {
            path.as_path().to_cow()
        };
        fs::write(out_path.as_ref(), data)
            .with_context(|| format!("Failed to write '{}'", out_path.display()))?;
    }
    Ok(())
}
