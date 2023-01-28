use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs::File,
    io::{BufRead, BufWriter, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use argh::FromArgs;
use object::{Object, ObjectSymbol, SymbolScope};

use crate::util::file::{buf_reader, map_file};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing static libraries.
#[argh(subcommand, name = "ar")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Create(CreateArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates a static library.
#[argh(subcommand, name = "create")]
pub struct CreateArgs {
    #[argh(positional)]
    /// output file
    out: PathBuf,
    #[argh(positional)]
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
    let mut files = Vec::with_capacity(args.files.len());
    for path in args.files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        match path_str.strip_prefix('@') {
            Some(rsp_file) => {
                let reader = buf_reader(rsp_file)?;
                for result in reader.lines() {
                    let line = result?;
                    if !line.is_empty() {
                        files.push(PathBuf::from(line));
                    }
                }
            }
            None => {
                files.push(path);
            }
        }
    }

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
    let out = BufWriter::new(File::create(&args.out)?);
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
