use std::path::PathBuf;

use anyhow::Result;
use argh::FromArgs;

use crate::util::rso::process_rso;

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing RSO files.
#[argh(subcommand, name = "rso")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views RSO file information.
#[argh(subcommand, name = "info")]
pub struct InfoArgs {
    #[argh(positional)]
    /// RSO file
    rso_file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let rso = process_rso(&args.rso_file)?;
    println!("Read RSO module {}", rso.name);
    Ok(())
}
