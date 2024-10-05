use std::fs::DirBuilder;

use anyhow::{bail, ensure, Result};
use argp::FromArgs;
use cwdemangle::{demangle, DemangleOptions};
use tracing::error;
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{
        config::{write_splits_file, write_symbols_file},
        map::{create_obj, process_map, SymbolEntry, SymbolRef},
        path::native_path,
        split::update_splits,
    },
    vfs::open_file,
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
    Config(ConfigArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all entries for a particular TU.
#[argp(subcommand, name = "entries")]
pub struct EntriesArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// path to input map
    map_file: Utf8NativePathBuf,
    #[argp(positional)]
    /// TU to display entries for
    unit: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Displays all references to a symbol.
#[argp(subcommand, name = "symbol")]
pub struct SymbolArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// path to input map
    map_file: Utf8NativePathBuf,
    #[argp(positional)]
    /// symbol to display references for
    symbol: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generates project configuration files from a map. (symbols.txt, splits.txt)
#[argp(subcommand, name = "config")]
pub struct ConfigArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// path to input map
    map_file: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output directory for symbols.txt and splits.txt
    out_dir: Utf8NativePathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Entries(c_args) => entries(c_args),
        SubCommand::Symbol(c_args) => symbol(c_args),
        SubCommand::Config(c_args) => config(c_args),
    }
}

fn entries(args: EntriesArgs) -> Result<()> {
    let mut file = open_file(&args.map_file, true)?;
    let entries = process_map(file.as_mut(), None, None)?;
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
    let mut file = open_file(&args.map_file, true)?;
    log::info!("Processing map...");
    let entries = process_map(file.as_mut(), None, None)?;
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

fn config(args: ConfigArgs) -> Result<()> {
    let mut file = open_file(&args.map_file, true)?;
    log::info!("Processing map...");
    let entries = process_map(file.as_mut(), None, None)?;
    let mut obj = create_obj(&entries)?;
    if let Err(e) = update_splits(&mut obj, None, false) {
        error!("Failed to update splits: {}", e)
    }
    DirBuilder::new().recursive(true).create(&args.out_dir)?;
    write_symbols_file(&args.out_dir.join("symbols.txt"), &obj, None)?;
    write_splits_file(&args.out_dir.join("splits.txt"), &obj, false, None)?;
    log::info!("Done!");
    Ok(())
}
