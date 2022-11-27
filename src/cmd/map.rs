use std::{fs::File, io::BufReader};

use anyhow::{Context, Error, Result};
use argh::FromArgs;

use crate::util::map::{process_map, SymbolEntry, SymbolRef};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing CodeWarrior maps.
#[argh(subcommand, name = "map")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Entries(EntriesArgs),
    Symbol(SymbolArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all entries for a particular TU.
#[argh(subcommand, name = "entries")]
pub struct EntriesArgs {
    #[argh(positional)]
    /// path to input map
    map_file: String,
    #[argh(positional)]
    /// TU to display entries for
    unit: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all references to a symbol.
#[argh(subcommand, name = "symbol")]
pub struct SymbolArgs {
    #[argh(positional)]
    /// path to input map
    map_file: String,
    #[argh(positional)]
    /// symbol to display references for
    symbol: String,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Entries(c_args) => entries(c_args),
        SubCommand::Symbol(c_args) => symbol(c_args),
    }
}

fn entries(args: EntriesArgs) -> Result<()> {
    let reader = BufReader::new(
        File::open(&args.map_file)
            .with_context(|| format!("Failed to open file '{}'", args.map_file))?,
    );
    let entries = process_map(reader)?;
    match entries.unit_entries.get_vec(&args.unit) {
        Some(vec) => {
            for symbol_ref in vec {
                if symbol_ref.name.starts_with('@') {
                    continue;
                }
                if let Some(symbol) = entries.symbols.get(symbol_ref) {
                    println!("{}", symbol.demangled.as_ref().unwrap_or(&symbol.name));
                } else {
                    println!("Symbol not found: {}", symbol_ref.name);
                }
            }
        }
        None => {
            return Err(Error::msg(format!(
                "Failed to find entries for TU '{}' in map",
                args.unit
            )));
        }
    }
    Ok(())
}

fn symbol(args: SymbolArgs) -> Result<()> {
    let reader = BufReader::new(
        File::open(&args.map_file)
            .with_context(|| format!("Failed to open file '{}'", args.map_file))?,
    );
    let entries = process_map(reader)?;
    let mut opt_ref: Option<(SymbolRef, SymbolEntry)> = None;
    for (symbol_ref, entry) in &entries.symbols {
        if symbol_ref.name == args.symbol {
            if opt_ref.is_some() {
                return Err(Error::msg(format!("Symbol '{}' found in multiple TUs", args.symbol)));
            }
            opt_ref = Some((symbol_ref.clone(), entry.clone()));
        }
    }
    match opt_ref {
        Some((symbol_ref, symbol)) => {
            println!("Located symbol {}", symbol.demangled.as_ref().unwrap_or(&symbol.name));
            if let Some(vec) = entries.entry_references.get_vec(&symbol_ref) {
                println!("\nReferences:");
                for x in vec {
                    if let Some(reference) = entries.symbols.get(x) {
                        println!(
                            ">>> {} ({:?},{:?}) [{}]",
                            reference.demangled.as_ref().unwrap_or(&reference.name),
                            reference.kind,
                            reference.visibility,
                            reference.unit
                        );
                    } else {
                        println!(">>> {} (NOT FOUND)", x.name);
                    }
                }
            }
            if let Some(vec) = entries.entry_referenced_from.get_vec(&symbol_ref) {
                println!("\nReferenced from:");
                for x in vec {
                    if let Some(reference) = entries.symbols.get(x) {
                        println!(
                            ">>> {} ({:?}, {:?}) [{}]",
                            reference.demangled.as_ref().unwrap_or(&reference.name),
                            reference.kind,
                            reference.visibility,
                            reference.unit
                        );
                    } else {
                        println!(">>> {} (NOT FOUND)", x.name);
                    }
                }
            }
            println!("\n");
        }
        None => {
            return Err(Error::msg(format!("Failed to find symbol '{}' in map", args.symbol)));
        }
    }
    Ok(())
}
