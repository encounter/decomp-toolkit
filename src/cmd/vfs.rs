use std::{
    fs,
    fs::File,
    io,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context};
use argp::FromArgs;
use size::Size;

use crate::vfs::{
    decompress_file, detect, open_path, FileFormat, OpenResult, Vfs, VfsFile, VfsFileType,
    VfsMetadata,
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
    #[argp(positional)]
    /// Directory or container path.
    pub path: PathBuf,
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
    #[argp(positional)]
    /// Source path(s) and destination path.
    pub paths: Vec<PathBuf>,
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
            widths[i] = widths[i].max(column.len());
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
            let filename = Path::new(path)
                .file_name()
                .ok_or_else(|| anyhow!("Path has no filename"))?
                .to_string_lossy();
            if args.short {
                println!("{}", filename);
            } else {
                let metadata = file
                    .metadata()
                    .with_context(|| format!("Failed to fetch metadata for {}", path))?;
                files.push(file_info(&filename, file.as_mut(), &metadata)?);
            }
        }
        OpenResult::Directory(mut fs, path) => {
            ls_directory(fs.as_mut(), path, "", &args, &mut files)?;
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
                    print!("{:width$}", column, width = widths[i]);
                }
            }
            println!();
        }
    }
    Ok(())
}

fn ls_directory(
    fs: &mut dyn Vfs,
    path: &str,
    base_filename: &str,
    args: &LsArgs,
    files: &mut Vec<Columns<5>>,
) -> anyhow::Result<()> {
    let entries = fs.read_dir(path)?;
    files.reserve(entries.len());
    for filename in entries {
        let entry_path = format!("{}/{}", path, filename);
        let display_filename = format!("{}{}", base_filename, filename);
        let metadata = fs
            .metadata(&entry_path)
            .with_context(|| format!("Failed to fetch metadata for {}", entry_path))?;
        match metadata.file_type {
            VfsFileType::File => {
                let mut file = fs
                    .open(&entry_path)
                    .with_context(|| format!("Failed to open file {}", entry_path))?;
                if args.short {
                    println!("{}", display_filename);
                } else {
                    files.push(file_info(&display_filename, file.as_mut(), &metadata)?);
                }
            }
            VfsFileType::Directory => {
                if args.short {
                    println!("{}/", display_filename);
                } else {
                    files.push([
                        "        ".to_string(),
                        format!("{}/", display_filename),
                        "Directory".to_string(),
                        String::new(),
                        String::new(),
                    ]);
                }
                if args.recursive {
                    let base_filename = format!("{}/", display_filename);
                    ls_directory(fs, &entry_path, &base_filename, args, files)?;
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
    let dest_is_dir = args.paths.len() > 1 || dest.metadata().ok().is_some_and(|m| m.is_dir());
    let auto_decompress = !args.no_decompress;
    for path in args.paths {
        match open_path(&path, auto_decompress)? {
            OpenResult::File(file, path) => {
                let dest = if dest_is_dir {
                    fs::create_dir_all(&dest).with_context(|| {
                        format!("Failed to create directory {}", dest.display())
                    })?;
                    let filename = Path::new(path)
                        .file_name()
                        .ok_or_else(|| anyhow!("Path has no filename"))?;
                    dest.join(filename)
                } else {
                    dest.clone()
                };
                cp_file(file, path, &dest, auto_decompress, args.quiet)?;
            }
            OpenResult::Directory(mut fs, path) => {
                cp_recursive(fs.as_mut(), path, &dest, auto_decompress, args.quiet)?;
            }
        }
    }
    Ok(())
}

fn cp_file(
    mut file: Box<dyn VfsFile>,
    path: &str,
    dest: &Path,
    auto_decompress: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut compression = None;
    if let FileFormat::Compressed(kind) = detect(file.as_mut())? {
        if auto_decompress {
            file = decompress_file(file.as_mut(), kind)
                .with_context(|| format!("Failed to decompress file {}", dest.display()))?;
            compression = Some(kind);
        }
    }
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to fetch metadata for {}", dest.display()))?;
    if !quiet {
        if let Some(kind) = compression {
            println!(
                "{} -> {} ({}) [Decompressed {}]",
                path,
                dest.display(),
                Size::from_bytes(metadata.len),
                kind
            );
        } else {
            println!("{} -> {} ({})", path, dest.display(), Size::from_bytes(metadata.len));
        }
    }
    let mut dest_file =
        File::create(dest).with_context(|| format!("Failed to create file {}", dest.display()))?;
    buf_copy(file.as_mut(), &mut dest_file)
        .with_context(|| format!("Failed to copy file {}", dest.display()))?;
    dest_file.flush().with_context(|| format!("Failed to flush file {}", dest.display()))?;
    Ok(())
}

fn buf_copy<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: BufRead + ?Sized,
    W: Write + ?Sized,
{
    let mut copied = 0;
    loop {
        let buf = reader.fill_buf()?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        writer.write_all(buf)?;
        reader.consume(len);
        copied += len as u64;
    }
    Ok(copied)
}

fn cp_recursive(
    fs: &mut dyn Vfs,
    path: &str,
    dest: &Path,
    auto_decompress: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    fs::create_dir_all(dest)
        .with_context(|| format!("Failed to create directory {}", dest.display()))?;
    let entries = fs.read_dir(path)?;
    for filename in entries {
        let entry_path = format!("{}/{}", path, filename);
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
