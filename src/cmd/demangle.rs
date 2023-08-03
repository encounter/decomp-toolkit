use anyhow::{anyhow, Result};
use argp::FromArgs;
use cwdemangle::{demangle, DemangleOptions};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Demangle a CodeWarrior C++ symbol.
#[argp(subcommand, name = "demangle")]
pub struct Args {
    #[argp(positional)]
    /// symbol to demangle
    symbol: String,
    #[argp(switch)]
    /// disable replacing `(void)` with `()`
    keep_void: bool,
}

pub fn run(args: Args) -> Result<()> {
    let options = DemangleOptions { omit_empty_parameters: !args.keep_void };
    match demangle(args.symbol.as_str(), &options) {
        Some(symbol) => {
            println!("{symbol}");
            Ok(())
        }
        None => Err(anyhow!("Failed to demangle symbol")),
    }
}
