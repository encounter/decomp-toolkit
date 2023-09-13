use std::path::PathBuf;

use anyhow::Result;
use argp::FromArgs;

use crate::util::{file::map_file, rso::process_rso};

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
        let file = map_file(args.rso_file)?;
        let obj = process_rso(&mut file.as_reader())?;
        #[allow(clippy::let_and_return)]
        obj
    };
    println!("Read RSO module {}", rso.name);
    Ok(())
}
