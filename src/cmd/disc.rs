use anyhow::{Error, Result};
use argp::FromArgs;
use nodtool::SubCommand;

#[derive(FromArgs, Debug)]
/// Commands for processing disc images.
#[argp(subcommand, name = "disc")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

pub fn run(args: Args) -> Result<()> { nodtool::run(args.command).map_err(Error::new) }
