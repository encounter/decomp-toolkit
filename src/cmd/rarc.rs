use std::{fs, fs::DirBuilder, path::PathBuf};

use anyhow::{Context, Result};
use argp::FromArgs;

use crate::util::{
    file::{decompress_if_needed, map_file},
    rarc::{Node, RarcReader},
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing RSO files.
#[argp(subcommand, name = "rarc")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    List(ListArgs),
    Extract(ExtractArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views RARC file information.
#[argp(subcommand, name = "list")]
pub struct ListArgs {
    #[argp(positional)]
    /// RARC file
    file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts RARC file contents.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional)]
    /// RARC file
    file: PathBuf,
    #[argp(option, short = 'o')]
    /// output directory
    output: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::List(c_args) => list(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
    }
}

fn list(args: ListArgs) -> Result<()> {
    let file = map_file(&args.file)?;
    let rarc = RarcReader::new(&mut file.as_reader())
        .with_context(|| format!("Failed to process RARC file '{}'", args.file.display()))?;

    let mut current_path = PathBuf::new();
    for node in rarc.nodes() {
        match node {
            Node::DirectoryBegin { name } => {
                current_path.push(name.name);
            }
            Node::DirectoryEnd { name: _ } => {
                current_path.pop();
            }
            Node::File { name, offset, size } => {
                let path = current_path.join(name.name);
                println!("{}: {} bytes, offset {:#X}", path.display(), size, offset);
            }
            Node::CurrentDirectory => {}
            Node::ParentDirectory => {}
        }
    }
    Ok(())
}

fn extract(args: ExtractArgs) -> Result<()> {
    let file = map_file(&args.file)?;
    let rarc = RarcReader::new(&mut file.as_reader())
        .with_context(|| format!("Failed to process RARC file '{}'", args.file.display()))?;

    let mut current_path = PathBuf::new();
    for node in rarc.nodes() {
        match node {
            Node::DirectoryBegin { name } => {
                current_path.push(name.name);
            }
            Node::DirectoryEnd { name: _ } => {
                current_path.pop();
            }
            Node::File { name, offset, size } => {
                let file_data = decompress_if_needed(
                    &file.as_slice()[offset as usize..offset as usize + size as usize],
                )?;
                let file_path = current_path.join(&name.name);
                let output_path =
                    args.output.as_ref().map(|p| p.join(&file_path)).unwrap_or_else(|| file_path);
                if let Some(parent) = output_path.parent() {
                    DirBuilder::new().recursive(true).create(parent)?;
                }
                fs::write(&output_path, file_data)
                    .with_context(|| format!("Failed to write file '{}'", output_path.display()))?;
            }
            Node::CurrentDirectory => {}
            Node::ParentDirectory => {}
        }
    }
    Ok(())
}
