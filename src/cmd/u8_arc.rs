use anyhow::Result;
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;

use super::vfs;
use crate::util::path::native_path;

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
    #[argp(positional, from_str_fn(native_path))]
    /// U8 (arc) file
    file: Utf8NativePathBuf,
    #[argp(switch, short = 's')]
    /// Only print filenames.
    short: bool,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts U8 (arc) file contents.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// U8 (arc) file
    file: Utf8NativePathBuf,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// output directory
    output: Option<Utf8NativePathBuf>,
    #[argp(switch)]
    /// Do not decompress files when copying.
    no_decompress: bool,
    #[argp(switch, short = 'q')]
    /// Quiet output. Don't print anything except errors.
    quiet: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::List(c_args) => list(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
    }
}

fn list(args: ListArgs) -> Result<()> {
    let path = Utf8NativePathBuf::from(format!("{}:", args.file));
    vfs::ls(vfs::LsArgs { path, short: args.short, recursive: true })
}

fn extract(args: ExtractArgs) -> Result<()> {
    let path = Utf8NativePathBuf::from(format!("{}:", args.file));
    let output = args.output.unwrap_or_else(|| Utf8NativePathBuf::from("."));
    vfs::cp(vfs::CpArgs {
        paths: vec![path, output],
        no_decompress: args.no_decompress,
        quiet: args.quiet,
    })
}
