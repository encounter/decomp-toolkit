use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs::File,
    io::Write,
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
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
    Extract(ExtractArgs),
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

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts a static library.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional)]
    /// input files
    files: Vec<PathBuf>,
    #[argp(option, short = 'o')]
    /// output directory
    out: Option<PathBuf>,
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
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        let identifier = path_str.as_bytes().to_vec();
        identifiers.push(identifier.clone());

        let entries = match symbol_table.entry(identifier) {
            Entry::Vacant(e) => e.insert(Vec::new()),
            Entry::Occupied(_) => bail!("Duplicate file name '{path_str}'"),
        };
        let file = map_file(path)?;
        let obj = object::File::parse(file.as_slice())?;
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

fn extract(args: ExtractArgs) -> Result<()> {
    // Process response files (starting with '@')
    let files = process_rsp(&args.files)?;

    // Extract files
    let mut num_files = 0;
    for path in &files {
        let mut out_dir = if let Some(out) = &args.out { out.clone() } else { PathBuf::new() };
        // If there are multiple files, extract to separate directories
        if files.len() > 1 {
            out_dir
                .push(path.with_extension("").file_name().ok_or_else(|| anyhow!("No file name"))?);
        }
        std::fs::create_dir_all(&out_dir)?;
        if !args.quiet {
            println!("Extracting {} to {}", path.display(), out_dir.display());
        }

        let file = map_file(path)?;
        let mut archive = ar::Archive::new(file.as_slice());
        while let Some(entry) = archive.next_entry() {
            let mut entry =
                entry.with_context(|| format!("Processing entry in {}", path.display()))?;
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
                .with_context(|| format!("Failed to create file {}", file_path.display()))?;
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
