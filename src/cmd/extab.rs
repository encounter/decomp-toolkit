use std::io::Write;

use anyhow::{Context, Result};
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;

use crate::{
    util,
    util::{
        dol::{process_dol, write_dol},
        elf::{is_elf_file, process_elf, write_elf},
        file::buf_writer,
        path::native_path,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing extab (exception table) data.
#[argp(subcommand, name = "extab")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Clean(CleanArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Rewrites extab data in a DOL or ELF file, replacing any uninitialized padding bytes.
#[argp(subcommand, name = "clean")]
pub struct CleanArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// Path to input file
    input: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// Path to output file
    output: Utf8NativePathBuf,
    #[argp(option, short = 'p')]
    /// Data to replace padding bytes with, encoded as a hexadecimal string. If not specified, padding bytes will be zeroed instead.
    padding: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Clean(clean_args) => clean_extab(clean_args),
    }
}

fn clean_extab(args: CleanArgs) -> Result<()> {
    let is_elf = is_elf_file(&args.input)?;
    let mut obj = if is_elf {
        process_elf(&args.input)?
    } else {
        let mut file = open_file(&args.input, true)?;
        let name = args.input.file_stem().unwrap_or_default();
        process_dol(file.map()?, name)?
    };
    let padding: Vec<u8> = match args.padding {
        None => Vec::new(),
        Some(padding_str) => {
            hex::decode(padding_str).context("Failed to decode padding bytes from hex")?
        }
    };
    let num_cleaned = util::extab::clean_extab(&mut obj, padding.iter().copied())?;
    tracing::debug!("Cleaned {num_cleaned} extab symbols");
    let mut out = buf_writer(&args.output)?;
    if is_elf {
        let data = write_elf(&obj, false)?;
        out.write_all(&data).context("Failed to write ELF")?;
    } else {
        write_dol(&obj, &mut out).context("Failed to write DOL")?;
    }
    Ok(())
}
