use std::path::PathBuf;

use anyhow::{bail, ensure, Result};
use argp::FromArgs;
use cwdemangle::{demangle, DemangleOptions};

use crate::util::{
    file::map_file,
    map::{process_map, SymbolEntry, SymbolRef},
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing CodeWarrior maps.
#[argp(subcommand, name = "map")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Entries(EntriesArgs),
    Symbol(SymbolArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all entries for a particular TU.
#[argp(subcommand, name = "entries")]
pub struct EntriesArgs {
    #[argp(positional)]
    /// path to input map
    map_file: PathBuf,
    #[argp(positional)]
    /// TU to display entries for
    unit: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all references to a symbol.
#[argp(subcommand, name = "symbol")]
pub struct SymbolArgs {
    #[argp(positional)]
    /// path to input map
    map_file: PathBuf,
    #[argp(positional)]
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
    let file = map_file(&args.map_file)?;
    let entries = process_map(&mut file.as_reader())?;
    match entries.unit_entries.get_vec(&args.unit) {
        Some(vec) => {
            println!("Entries for {}:", args.unit);
            for symbol_ref in vec {
                if symbol_ref.name.starts_with('@') {
                    continue;
                }
                if let Some((section, entry)) = entries.get_section_symbol(symbol_ref) {
                    println!(
                        ">>> {} ({:?},{:?}) @ {}:{:#010X} [{}]",
                        entry.demangled.as_ref().unwrap_or(&entry.name),
                        entry.kind,
                        entry.visibility,
                        section,
                        entry.address,
                        entry.unit.as_deref().unwrap_or("(generated)"),
                    );
                } else {
                    let demangled = demangle(&symbol_ref.name, &DemangleOptions::default());
                    println!(">>> {}", demangled.as_deref().unwrap_or(&symbol_ref.name));
                }
            }
        }
        None => bail!("Failed to find entries for TU '{}' in map", args.unit),
    }
    Ok(())
}

fn symbol(args: SymbolArgs) -> Result<()> {
    let file = map_file(&args.map_file)?;
    log::info!("Processing map...");
    let entries = process_map(&mut file.as_reader())?;
    log::info!("Done!");
    let mut opt_ref: Option<(String, SymbolEntry)> = None;

    for (section, symbol_map) in &entries.section_symbols {
        for symbol_entry in symbol_map.values().flatten() {
            if symbol_entry.name == args.symbol {
                ensure!(opt_ref.is_none(), "Found multiple symbols with name '{}'", args.symbol);
                opt_ref = Some((section.clone(), symbol_entry.clone()));
            }
        }
    }
    let Some((section, symbol)) = opt_ref else {
        bail!("Failed to find symbol '{}' in map", args.symbol);
    };

    println!(
        "Located symbol {} ({:?},{:?}) @ {}:{:#010X} [{}]",
        symbol.demangled.as_ref().unwrap_or(&symbol.name),
        symbol.kind,
        symbol.visibility,
        section,
        symbol.address,
        symbol.unit.as_deref().unwrap_or("(generated)"),
    );
    let symbol_ref = SymbolRef { name: symbol.name.clone(), unit: symbol.unit.clone() };
    if let Some(vec) = entries.entry_references.get_vec(&symbol_ref) {
        println!("\nKnown references:");
        for x in vec {
            if let Some((section, entry)) = entries.get_section_symbol(x) {
                println!(
                    ">>> {} ({:?},{:?}) @ {}:{:#010X} [{}]",
                    entry.demangled.as_ref().unwrap_or(&entry.name),
                    entry.kind,
                    entry.visibility,
                    section,
                    entry.address,
                    entry.unit.as_deref().unwrap_or("(generated)"),
                );
            } else {
                println!(">>> {} (NOT FOUND)", x.name);
            }
        }
    }
    if let Some(vec) = entries.entry_referenced_from.get_vec(&symbol_ref) {
        println!("\nKnown referenced from:");
        for x in vec {
            if let Some((section, entry)) = entries.get_section_symbol(x) {
                println!(
                    ">>> {} ({:?}, {:?}) @ {}:{:#010X} [{}]",
                    entry.demangled.as_ref().unwrap_or(&entry.name),
                    entry.kind,
                    entry.visibility,
                    section,
                    entry.address,
                    entry.unit.as_deref().unwrap_or("(generated)"),
                );
            } else {
                println!(">>> {} (NOT FOUND)", x.name);
            }
        }
    }
    if let Some(vec) = entries.unit_references.get_vec(&symbol_ref) {
        println!("\nGenerated in TUs:");
        for x in vec {
            println!(">>> {}", x);
        }
    }
    println!("\n");
    Ok(())
}
