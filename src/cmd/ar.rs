use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs::File,
    io::Write,
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use object::{Object, ObjectSymbol, SymbolScope};
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{
        file::{buf_writer, process_rsp},
        path::native_path,
    },
    vfs::open_file,
};

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
    Extract(ExtractArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates a static library.
#[argp(subcommand, name = "create")]
pub struct CreateArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// output file
    out: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// input files
    files: Vec<Utf8NativePathBuf>,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts a static library.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input files
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// output directory
    out: Option<Utf8NativePathBuf>,
    #[argp(switch, short = 'q')]
    /// quiet output
    quiet: bool,
    #[argp(switch, short = 'v')]
    /// verbose output
    verbose: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Create(c_args) => create(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
    }
}

fn create(args: CreateArgs) -> Result<()> {
    // Process response files (starting with '@')
    let files = process_rsp(&args.files)?;

    // Build identifiers & symbol table
    let mut identifiers = Vec::with_capacity(files.len());
    let mut symbol_table = BTreeMap::new();
    for path in &files {
        let unix_path = path.with_unix_encoding();
        let identifier = unix_path.as_str().as_bytes().to_vec();
        identifiers.push(identifier.clone());

        let entries = match symbol_table.entry(identifier) {
            Entry::Vacant(e) => e.insert(Vec::new()),
            Entry::Occupied(_) => bail!("Duplicate file name '{unix_path}'"),
        };
        let mut file = open_file(path, false)?;
        let obj = object::File::parse(file.map()?)?;
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
        let mut file = File::open(&path)?;
        builder.append_file(path.as_str().as_bytes(), &mut file)?;
    }
    builder.into_inner()?.flush()?;
    Ok(())
}

fn extract(args: ExtractArgs) -> Result<()> {
    // Process response files (starting with '@')
    let files = process_rsp(&args.files)?;

    // Extract files
    let mut num_files = 0;
    for path in &files {
        let mut out_dir =
            if let Some(out) = &args.out { out.clone() } else { Utf8NativePathBuf::new() };
        // If there are multiple files, extract to separate directories
        if files.len() > 1 {
            out_dir
                .push(path.with_extension("").file_name().ok_or_else(|| anyhow!("No file name"))?);
        }
        std::fs::create_dir_all(&out_dir)?;
        if !args.quiet {
            println!("Extracting {} to {}", path, out_dir);
        }

        let mut file = open_file(path, false)?;
        let mut archive = ar::Archive::new(file.map()?);
        while let Some(entry) = archive.next_entry() {
            let mut entry = entry.with_context(|| format!("Processing entry in {}", path))?;
            let file_name = std::str::from_utf8(entry.header().identifier())?;
            if !args.quiet && args.verbose {
                println!("\t{}", file_name);
            }
            let mut file_path = out_dir.clone();
            for segment in file_name.split(&['/', '\\']) {
                file_path.push(sanitise_file_name::sanitise(segment));
            }
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = File::create(&file_path)
                .with_context(|| format!("Failed to create file {}", file_path))?;
            std::io::copy(&mut entry, &mut file)?;
            file.flush()?;

            num_files += 1;
        }
    }
    if !args.quiet {
        println!("Extracted {} files", num_files);
    }
    Ok(())
}
