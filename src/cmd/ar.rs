use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use argh::FromArgs;
use object::{Object, ObjectSymbol, SymbolScope};

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
                let reader = BufReader::new(
                    File::open(rsp_file)
                        .with_context(|| format!("Failed to open file '{rsp_file}'"))?,
                );
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
        let object_file = File::open(path)
            .with_context(|| format!("Failed to open object file '{}'", path.display()))?;
        let map = unsafe { memmap2::MmapOptions::new().map(&object_file) }
            .with_context(|| format!("Failed to mmap object file: '{}'", path.display()))?;
        let obj = object::File::parse(map.as_ref())?;
        for symbol in obj.symbols() {
            if symbol.scope() == SymbolScope::Dynamic {
                entries.push(symbol.name_bytes()?.to_vec());
            }
        }
    }

    // Write archive
    let out = BufWriter::new(File::create(&args.out)?);
    let mut builder =
        ar::GnuBuilder::new(out, identifiers, ar::GnuSymbolTableFormat::Size32, symbol_table)?;
    for path in files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        let mut file = File::open(&path)?;
        builder.append_file(path_str.as_bytes(), &mut file)?;
    }
    builder.into_inner()?.flush()?;
    Ok(())
}
