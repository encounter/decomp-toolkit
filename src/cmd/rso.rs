use std::path::PathBuf;

use anyhow::{Context, Result};
use argp::FromArgs;

use crate::util::{
    file::{decompress_if_needed, map_file, Reader},
    rso::process_rso,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing RSO files.
#[argp(subcommand, name = "rso")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views RSO file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// RSO file
    rso_file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let rso = {
        let file = map_file(&args.rso_file)?;
        let data = decompress_if_needed(file.as_slice())
            .with_context(|| format!("Failed to decompress '{}'", args.rso_file.display()))?;
        process_rso(&mut Reader::new(data.as_ref()))?
    };
    println!("Read RSO module {}", rso.name);
    Ok(())
}
