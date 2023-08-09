use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs::File,
    io::Write,
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use argp::FromArgs;
use object::{Object, ObjectSymbol, SymbolScope};

use crate::util::file::{buf_writer, map_file, process_rsp};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing static libraries.
#[argp(subcommand, name = "ar")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Create(CreateArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates a static library.
#[argp(subcommand, name = "create")]
pub struct CreateArgs {
    #[argp(positional)]
    /// output file
    out: PathBuf,
    #[argp(positional)]
    /// input files
    files: Vec<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Create(c_args) => create(c_args),
    }
}

fn create(args: CreateArgs) -> Result<()> {
    // Process response files (starting with '@')
    let files = process_rsp(&args.files)?;

    // Build identifiers & symbol table
    let mut identifiers = Vec::with_capacity(files.len());
    let mut symbol_table = BTreeMap::new();
    for path in &files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        let identifier = path_str.as_bytes().to_vec();
        identifiers.push(identifier.clone());

        let entries = match symbol_table.entry(identifier) {
            Entry::Vacant(e) => e.insert(Vec::new()),
            Entry::Occupied(_) => bail!("Duplicate file name '{path_str}'"),
        };
        let mmap = map_file(path)?;
        let obj = object::File::parse(&*mmap)?;
        for symbol in obj.symbols() {
            if symbol.scope() == SymbolScope::Dynamic {
                entries.push(symbol.name_bytes()?.to_vec());
            }
        }
    }

    // Write archive
    let out = buf_writer(&args.out)?;
    let mut builder = ar::GnuBuilder::new_with_symbol_table(
        out,
        true,
        identifiers,
        ar::GnuSymbolTableFormat::Size32,
        symbol_table,
    )?;
    for path in files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        let mut file = File::open(&path)?;
        builder.append_file(path_str.as_bytes(), &mut file)?;
    }
    builder.into_inner()?.flush()?;
    Ok(())
}
