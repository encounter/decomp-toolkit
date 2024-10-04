use std::{fs::File, io, io::Write, path::PathBuf};

use anyhow::{anyhow, bail};
use argp::FromArgs;
use nodtool::nod::ResultContext;

use crate::vfs::{decompress_file, detect, open_fs, FileFormat, StdFs, Vfs, VfsFileType};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for interacting with discs and containers.
#[argp(subcommand, name = "vfs")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Ls(LsArgs),
    Cp(CpArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// List files in a directory or container.
#[argp(subcommand, name = "ls")]
pub struct LsArgs {
    #[argp(positional)]
    /// Path to the container.
    path: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Copy files from a container.
#[argp(subcommand, name = "cp")]
pub struct CpArgs {
    #[argp(positional)]
    /// Source path(s) and destination path.
    paths: Vec<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        SubCommand::Ls(args) => ls(args),
        SubCommand::Cp(args) => cp(args),
    }
}

fn find(path: &str) -> anyhow::Result<(Box<dyn Vfs>, &str)> {
    let mut split = path.split(':');
    let mut fs: Box<dyn Vfs> = Box::new(StdFs);
    let mut path = split.next().unwrap();
    for next in split {
        let mut file = fs.open(path)?;
        match detect(file.as_mut())? {
            FileFormat::Archive(kind) => {
                fs = open_fs(file, kind)?;
                path = next;
            }
            _ => bail!("'{}' is not a container", path),
        }
    }
    Ok((fs, path))
}

fn ls(args: LsArgs) -> anyhow::Result<()> {
    let str = args.path.to_str().ok_or_else(|| anyhow!("Path is not valid UTF-8"))?;
    let (mut fs, mut path) = find(str)?;
    let metadata = fs.metadata(path)?;
    if metadata.is_file() {
        let mut file = fs.open(path)?;
        match detect(file.as_mut())? {
            FileFormat::Archive(kind) => {
                fs = open_fs(file, kind)?;
                path = "";
            }
            _ => bail!("'{}' is not a directory", path),
        }
    }
    let entries = fs.read_dir(path)?;
    for entry in entries {
        println!("{}", entry);
    }
    Ok(())
}

fn cp(mut args: CpArgs) -> anyhow::Result<()> {
    if args.paths.len() < 2 {
        bail!("Both source and destination paths must be provided");
    }
    let dest = args.paths.pop().unwrap();
    let dest_is_dir = args.paths.len() > 1 || dest.metadata().ok().is_some_and(|m| m.is_dir());
    for path in args.paths {
        let str = path.to_str().ok_or_else(|| anyhow!("Path is not valid UTF-8"))?;
        let (mut fs, path) = find(str)?;
        let metadata = fs.metadata(path)?;
        match metadata.file_type {
            VfsFileType::File => {
                let mut file = fs.open(path)?;
                if let FileFormat::Compressed(kind) = detect(file.as_mut())? {
                    file = decompress_file(file, kind)?;
                }
                let dest = if dest_is_dir {
                    let name = path.rsplit('/').next().unwrap();
                    dest.join(name)
                } else {
                    dest.clone()
                };
                let mut dest_file = File::create(&dest)
                    .with_context(|| format!("Failed to create file {}", dest.display()))?;
                io::copy(file.as_mut(), &mut dest_file)
                    .with_context(|| format!("Failed to write file {}", dest.display()))?;
                dest_file
                    .flush()
                    .with_context(|| format!("Failed to flush file {}", dest.display()))?;
            }
            VfsFileType::Directory => bail!("Cannot copy directory"),
        }
    }
    Ok(())
}
