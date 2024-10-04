use std::{
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::Result;
use argp::FromArgs;

use crate::{
    cmd,
    util::{
        alf::AlfFile,
        file::buf_writer,
        reader::{Endian, FromReader},
    },
    vfs::open_path,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing NVIDIA Shield TV alf files.
#[argp(subcommand, name = "alf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Hashes(HashesArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Prints information about an alf file. (Same as `dol info`)
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// alf file
    file: PathBuf,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Extracts symbol hashes from an alf file.
#[argp(subcommand, name = "hashes")]
pub struct HashesArgs {
    #[argp(positional)]
    /// alf file
    alf_file: PathBuf,
    #[argp(positional)]
    /// output file
    output: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Hashes(c_args) => hashes(c_args),
    }
}

fn hashes(args: HashesArgs) -> Result<()> {
    let alf_file = {
        let mut file = open_path(&args.alf_file, true)?;
        AlfFile::from_reader(file.as_mut(), Endian::Little)?
    };
    let mut w: Box<dyn Write> = if let Some(output) = args.output {
        Box::new(buf_writer(output)?)
    } else {
        Box::new(stdout())
    };
    let mut symbols = alf_file.symbols.clone();
    symbols.sort_by_key(|s| s.address);
    for symbol in symbols {
        writeln!(
            w,
            "{:#010X} | {} | {:?} | {} | {} | {:#X}",
            symbol.address,
            symbol.section,
            symbol.kind,
            symbol.name,
            symbol.demangled_name,
            symbol.size
        )?;
    }
    w.flush()?;
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    cmd::dol::info(cmd::dol::InfoArgs { dol_file: args.file, selfile: None })
}
