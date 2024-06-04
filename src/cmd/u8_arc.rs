use std::{borrow::Cow, fs, fs::DirBuilder, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use argp::FromArgs;
use itertools::Itertools;

use crate::util::{
    file::{decompress_if_needed, map_file},
    u8_arc::{U8Node, U8View},
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing U8 (arc) files.
#[argp(subcommand, name = "u8")]
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
/// Views U8 (arc) file information.
#[argp(subcommand, name = "list")]
pub struct ListArgs {
    #[argp(positional)]
    /// U8 (arc) file
    file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts U8 (arc) file contents.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional)]
    /// U8 (arc) file
    file: PathBuf,
    #[argp(option, short = 'o')]
    /// output directory
    output: Option<PathBuf>,
    #[argp(switch, short = 'q')]
    /// quiet output
    quiet: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::List(c_args) => list(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
    }
}

fn list(args: ListArgs) -> Result<()> {
    let file = map_file(&args.file)?;
    let view = U8View::new(file.as_slice())
        .map_err(|e| anyhow!("Failed to open U8 file '{}': {}", args.file.display(), e))?;
    visit_files(&view, |_, node, path| {
        println!("{}: {} bytes, offset {:#X}", path, node.length(), node.offset());
        Ok(())
    })
}

fn extract(args: ExtractArgs) -> Result<()> {
    let file = map_file(&args.file)?;
    let view = U8View::new(file.as_slice())
        .map_err(|e| anyhow!("Failed to open U8 file '{}': {}", args.file.display(), e))?;
    visit_files(&view, |_, node, path| {
        let offset = node.offset();
        let size = node.length();
        let file_data = decompress_if_needed(
            &file.as_slice()[offset as usize..offset as usize + size as usize],
        )?;
        let output_path = args
            .output
            .as_ref()
            .map(|p| p.join(&path))
            .unwrap_or_else(|| PathBuf::from(path.clone()));
        if !args.quiet {
            println!("Extracting {} to {} ({} bytes)", path, output_path.display(), size);
        }
        if let Some(parent) = output_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        fs::write(&output_path, file_data)
            .with_context(|| format!("Failed to write file '{}'", output_path.display()))?;
        Ok(())
    })
}

fn visit_files(
    view: &U8View,
    mut visitor: impl FnMut(usize, &U8Node, String) -> Result<()>,
) -> Result<()> {
    let mut path_segments = Vec::<(Cow<str>, usize)>::new();
    for (idx, node, name) in view.iter() {
        // Remove ended path segments
        let mut new_size = 0;
        for (_, end) in path_segments.iter() {
            if *end == idx {
                break;
            }
            new_size += 1;
        }
        path_segments.truncate(new_size);

        // Add the new path segment
        let end = if node.is_dir() { node.length() as usize } else { idx + 1 };
        path_segments.push((name.map_err(|e| anyhow!("{}", e))?, end));

        let path = path_segments.iter().map(|(name, _)| name.as_ref()).join("/");
        if !node.is_dir() {
            visitor(idx, node, path)?;
        }
    }
    Ok(())
}
