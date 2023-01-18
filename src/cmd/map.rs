use std::{fs::File, io::BufReader};

use anyhow::{bail, ensure, Context, Result};
use argh::FromArgs;

use crate::util::map::{process_map, resolve_link_order, SymbolEntry, SymbolRef};

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
    Order(OrderArgs),
    Slices(SlicesArgs),
    Symbols(SymbolsArgs),
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

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Attempts to resolve global link order.
#[argh(subcommand, name = "order")]
pub struct OrderArgs {
    #[argh(positional)]
    /// path to input map
    map_file: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Emits a slices.yml for ppcdis. (WIP)
#[argh(subcommand, name = "slices")]
pub struct SlicesArgs {
    #[argh(positional)]
    /// path to input map
    map_file: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Emits a symbols.yml for ppcdis. (WIP)
#[argh(subcommand, name = "symbols")]
pub struct SymbolsArgs {
    #[argh(positional)]
    /// path to input map
    map_file: String,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Entries(c_args) => entries(c_args),
        SubCommand::Symbol(c_args) => symbol(c_args),
        SubCommand::Order(c_args) => order(c_args),
        SubCommand::Slices(c_args) => slices(c_args),
        SubCommand::Symbols(c_args) => symbols(c_args),
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
        None => bail!("Failed to find entries for TU '{}' in map", args.unit),
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
            ensure!(opt_ref.is_none(), "Symbol '{}' found in multiple TUs", args.symbol);
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
                            reference.unit.as_deref().unwrap_or("[generated]")
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
                            reference.unit.as_deref().unwrap_or("[generated]")
                        );
                    } else {
                        println!(">>> {} (NOT FOUND)", x.name);
                    }
                }
            }
            println!("\n");
        }
        None => bail!("Failed to find symbol '{}' in map", args.symbol),
    }
    Ok(())
}

fn order(args: OrderArgs) -> Result<()> {
    let reader = BufReader::new(
        File::open(&args.map_file)
            .with_context(|| format!("Failed to open file '{}'", args.map_file))?,
    );
    let entries = process_map(reader)?;
    let order = resolve_link_order(&entries.unit_order)?;
    for unit in order {
        println!("{unit}");
    }
    Ok(())
}

fn slices(args: SlicesArgs) -> Result<()> {
    let reader = BufReader::new(
        File::open(&args.map_file)
            .with_context(|| format!("Failed to open file '{}'", args.map_file))?,
    );
    let entries = process_map(reader)?;
    let order = resolve_link_order(&entries.unit_order)?;
    for unit in order {
        let unit_path = if let Some((lib, name)) = unit.split_once(' ') {
            format!("{}/{}", lib.strip_suffix(".a").unwrap_or(lib), name)
        } else if let Some(strip) = unit.strip_suffix(".o") {
            format!("{strip}.c")
        } else {
            unit.clone()
        };
        println!("{unit_path}:");
        // let mut ranges = Vec::<(String, Range<u32>)>::new();
        // match entries.unit_section_ranges.get(&unit) {
        //     Some(sections) => {
        //         for (name, range) in sections {
        //             ranges.push((name.clone(), range.clone()));
        //         }
        //     }
        //     None => bail!("Failed to locate sections for unit '{unit}'"),
        // }
        // ranges.sort_by(|(_, a), (_, b)| a.start.cmp(&b.start));
        // for (name, range) in ranges {
        //     println!("\t{}: [{:#010x}, {:#010x}]", name, range.start, range.end);
        // }
    }
    Ok(())
}

fn symbols(args: SymbolsArgs) -> Result<()> {
    let reader = BufReader::new(
        File::open(&args.map_file)
            .with_context(|| format!("Failed to open file '{}'", args.map_file))?,
    );
    let _entries = process_map(reader)?;
    // for (address, symbol) in entries.address_to_symbol {
    //     if symbol.name.starts_with('@') {
    //         continue;
    //     }
    //     println!("{:#010x}: {}", address, symbol.name);
    // }
    Ok(())
}
