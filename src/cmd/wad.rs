use anyhow::Result;
use argp::FromArgs;
use size::Size;
use typed_path::Utf8NativePathBuf;

use crate::{
    cmd::vfs,
    util::{
        path::native_path,
        wad::{process_wad, verify_wad},
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing Wii WAD files.
#[argp(subcommand, name = "wad")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Extract(ExtractArgs),
    Info(InfoArgs),
    Verify(VerifyArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts WAD file contents.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// WAD file
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

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views WAD file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// WAD file
    file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Verifies WAD file integrity.
#[argp(subcommand, name = "verify")]
pub struct VerifyArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// WAD file
    file: Utf8NativePathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Verify(c_args) => verify(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let mut file = open_file(&args.file, true)?;
    let wad = process_wad(file.as_mut())?;
    println!("Title ID: {}", hex::encode(wad.ticket().title_id));
    println!("Title key: {}", hex::encode(wad.title_key));
    println!("Fake signed: {}", wad.fake_signed);
    for content in wad.contents() {
        println!(
            "Content {:08x}: Offset {:#X}, size {}",
            content.content_index.get(),
            wad.content_offset(content.content_index.get()),
            Size::from_bytes(content.size.get())
        );
    }
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let mut file = open_file(&args.file, true)?;
    let wad = process_wad(file.as_mut())?;
    verify_wad(&wad, file.as_mut())?;
    println!("Verification successful");
    Ok(())
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
