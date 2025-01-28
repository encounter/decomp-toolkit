use std::{fs, fs::File, io::Write};

use anyhow::{anyhow, bail, Context};
use argp::FromArgs;
use size::Size;
use typed_path::{Utf8NativePath, Utf8NativePathBuf, Utf8UnixPath};
use unicode_width::UnicodeWidthStr;

use crate::{
    util::{file::buf_copy, path::native_path},
    vfs::{
        decompress_file, detect, open_path, FileFormat, OpenResult, Vfs, VfsFile, VfsFileType,
        VfsMetadata,
    },
};

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
    #[argp(positional, from_str_fn(native_path))]
    /// Directory or container path.
    pub path: Utf8NativePathBuf,
    #[argp(switch, short = 's')]
    /// Only print filenames.
    pub short: bool,
    #[argp(switch, short = 'r')]
    /// Recursively list files in directories.
    pub recursive: bool,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Copy files from a container.
#[argp(subcommand, name = "cp")]
pub struct CpArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// Source path(s) and destination path.
    pub paths: Vec<Utf8NativePathBuf>,
    #[argp(switch)]
    /// Do not decompress files when copying.
    pub no_decompress: bool,
    #[argp(switch, short = 'q')]
    /// Quiet output. Don't print anything except errors.
    pub quiet: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        SubCommand::Ls(args) => ls(args),
        SubCommand::Cp(args) => cp(args),
    }
}

const SEPARATOR: &str = " | ";
type Columns<const N: usize> = [String; N];

fn column_widths<const N: usize>(entries: &[Columns<N>]) -> [usize; N] {
    let mut widths = [0usize; N];
    for text in entries {
        for (i, column) in text.iter().enumerate() {
            widths[i] = widths[i].max(column.width_cjk());
        }
    }
    widths
}

fn file_info(
    filename: &str,
    file: &mut dyn VfsFile,
    metadata: &VfsMetadata,
) -> anyhow::Result<Columns<5>> {
    let format =
        detect(file).with_context(|| format!("Failed to detect file format for {}", filename))?;
    let mut info: Columns<5> = [
        Size::from_bytes(metadata.len).to_string(),
        filename.to_string(),
        format.to_string(),
        String::new(),
        String::new(),
    ];
    if let FileFormat::Compressed(kind) = format {
        let mut decompressed = decompress_file(file, kind)?;
        let metadata = decompressed
            .metadata()
            .with_context(|| format!("Failed to fetch metadata for {}", filename))?;
        let format = detect(decompressed.as_mut())
            .with_context(|| format!("Failed to detect file format for {}", filename))?;
        info[3] = format!("Decompressed: {}", Size::from_bytes(metadata.len));
        info[4] = format.to_string();
    }
    Ok(info)
}

pub fn ls(args: LsArgs) -> anyhow::Result<()> {
    let mut files = Vec::new();
    match open_path(&args.path, false)? {
        OpenResult::File(mut file, path) => {
            let filename = path.file_name().ok_or_else(|| anyhow!("Path has no filename"))?;
            if args.short {
                println!("{}", filename);
            } else {
                let metadata = file
                    .metadata()
                    .with_context(|| format!("Failed to fetch metadata for {}", path))?;
                files.push(file_info(filename, file.as_mut(), &metadata)?);
            }
        }
        OpenResult::Directory(mut fs, path) => {
            ls_directory(fs.as_mut(), &path, Utf8UnixPath::new(""), &args, &mut files)?;
        }
    }
    if !args.short {
        let widths = column_widths(&files);
        for entry in files {
            let mut written = 0;
            for (i, column) in entry.iter().enumerate() {
                if widths[i] > 0 {
                    if written > 0 {
                        print!("{}", SEPARATOR);
                    }
                    written += 1;
                    print!("{}", column);
                    let remain = widths[i].saturating_sub(column.width_cjk());
                    if remain > 0 {
                        print!("{:width$}", "", width = remain);
                    }
                }
            }
            println!();
        }
    }
    Ok(())
}

fn ls_directory(
    fs: &mut dyn Vfs,
    path: &Utf8UnixPath,
    base_filename: &Utf8UnixPath,
    args: &LsArgs,
    files: &mut Vec<Columns<5>>,
) -> anyhow::Result<()> {
    let entries = fs.read_dir(path)?;
    files.reserve(entries.len());
    for filename in entries {
        let entry_path = path.join(&filename);
        let display_path = base_filename.join(&filename);
        let metadata = fs
            .metadata(&entry_path)
            .with_context(|| format!("Failed to fetch metadata for {}", entry_path))?;
        match metadata.file_type {
            VfsFileType::File => {
                let mut file = fs
                    .open(&entry_path)
                    .with_context(|| format!("Failed to open file {}", entry_path))?;
                if args.short {
                    println!("{}", display_path);
                } else {
                    files.push(file_info(display_path.as_str(), file.as_mut(), &metadata)?);
                }
            }
            VfsFileType::Directory => {
                if args.short {
                    println!("{}/", display_path);
                } else {
                    files.push([
                        "        ".to_string(),
                        format!("{}/", display_path),
                        "Directory".to_string(),
                        String::new(),
                        String::new(),
                    ]);
                }
                if args.recursive {
                    ls_directory(fs, &entry_path, &display_path, args, files)?;
                }
            }
        }
    }
    Ok(())
}

pub fn cp(mut args: CpArgs) -> anyhow::Result<()> {
    if args.paths.len() < 2 {
        bail!("Both source and destination paths must be provided");
    }
    let dest = args.paths.pop().unwrap();
    let dest_is_dir = args.paths.len() > 1 || fs::metadata(&dest).ok().is_some_and(|m| m.is_dir());
    let auto_decompress = !args.no_decompress;
    for path in args.paths {
        match open_path(&path, auto_decompress)? {
            OpenResult::File(file, path) => {
                let dest = if dest_is_dir {
                    fs::create_dir_all(&dest)
                        .with_context(|| format!("Failed to create directory {}", dest))?;
                    let filename =
                        path.file_name().ok_or_else(|| anyhow!("Path has no filename"))?;
                    dest.join(filename)
                } else {
                    dest.clone()
                };
                cp_file(file, &path, &dest, auto_decompress, args.quiet)?;
            }
            OpenResult::Directory(mut fs, path) => {
                cp_recursive(fs.as_mut(), &path, &dest, auto_decompress, args.quiet)?;
            }
        }
    }
    Ok(())
}

fn cp_file(
    mut file: Box<dyn VfsFile>,
    path: &Utf8UnixPath,
    dest: &Utf8NativePath,
    auto_decompress: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut compression = None;
    if let FileFormat::Compressed(kind) = detect(file.as_mut())? {
        if auto_decompress {
            file = decompress_file(file.as_mut(), kind)
                .with_context(|| format!("Failed to decompress file {}", dest))?;
            compression = Some(kind);
        }
    }
    let metadata =
        file.metadata().with_context(|| format!("Failed to fetch metadata for {}", dest))?;
    if !quiet {
        if let Some(kind) = compression {
            println!(
                "{} -> {} ({}) [Decompressed {}]",
                path,
                dest,
                Size::from_bytes(metadata.len),
                kind
            );
        } else {
            println!("{} -> {} ({})", path, dest, Size::from_bytes(metadata.len));
        }
    }
    let mut dest_file =
        File::create(dest).with_context(|| format!("Failed to create file {}", dest))?;
    buf_copy(file.as_mut(), &mut dest_file)
        .with_context(|| format!("Failed to copy file {}", dest))?;
    dest_file.flush().with_context(|| format!("Failed to flush file {}", dest))?;
    Ok(())
}

fn cp_recursive(
    fs: &mut dyn Vfs,
    path: &Utf8UnixPath,
    dest: &Utf8NativePath,
    auto_decompress: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("Failed to create directory {}", dest))?;
    let entries = fs.read_dir(path)?;
    for filename in entries {
        let entry_path = path.join(&filename);
        let metadata = fs
            .metadata(&entry_path)
            .with_context(|| format!("Failed to fetch metadata for {}", entry_path))?;
        match metadata.file_type {
            VfsFileType::File => {
                let file = fs
                    .open(&entry_path)
                    .with_context(|| format!("Failed to open file {}", entry_path))?;
                cp_file(file, &entry_path, &dest.join(filename), auto_decompress, quiet)?;
            }
            VfsFileType::Directory => {
                cp_recursive(fs, &entry_path, &dest.join(filename), auto_decompress, quiet)?;
            }
        }
    }
    Ok(())
}
