use std::{
    fs::File,
    io::{stdout, BufRead, Read, Write},
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use owo_colors::{OwoColorize, Stream};
use sha1::{Digest, Sha1};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    util::{
        file::{buf_writer, process_rsp, touch},
        path::native_path,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Print or check SHA1 (160-bit) checksums.
#[argp(subcommand, name = "shasum")]
pub struct Args {
    #[argp(switch, short = 'c')]
    /// check SHA sums against given list
    check: bool,
    #[argp(positional, from_str_fn(native_path))]
    /// path to input file(s)
    files: Vec<Utf8NativePathBuf>,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// (check) touch output file on successful check
    /// (hash) write hash(es) to output file
    output: Option<Utf8NativePathBuf>,
    #[argp(switch, short = 'q')]
    /// only print failures and a summary
    quiet: bool,
}

const DEFAULT_BUF_SIZE: usize = 8192;

pub fn run(args: Args) -> Result<()> {
    if args.check {
        for path in process_rsp(&args.files)? {
            let mut file = open_file(&path, false)?;
            check(&args, file.as_mut())?;
        }
        if let Some(out_path) = &args.output {
            touch(out_path).with_context(|| format!("Failed to touch output file '{out_path}'"))?;
        }
    } else {
        let mut w: Box<dyn Write> = if let Some(out_path) = &args.output {
            Box::new(
                buf_writer(out_path)
                    .with_context(|| format!("Failed to open output file '{out_path}'"))?,
            )
        } else {
            Box::new(stdout())
        };
        for path in process_rsp(&args.files)? {
            let mut file = open_file(&path, false)?;
            hash(w.as_mut(), file.as_mut(), &path)?
        }
    }
    Ok(())
}

fn check<R>(args: &Args, reader: &mut R) -> Result<()>
where R: BufRead + ?Sized {
    let mut matches = 0usize;
    let mut mismatches = 0usize;
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => bail!("File read failed: {e}"),
        };
        let (hash, file_name) =
            line.split_once(' ').ok_or_else(|| anyhow!("Invalid line: {line}"))?;
        let file_name = match file_name.chars().next() {
            Some(' ') | Some('*') => &file_name[1..],
            _ => bail!("Invalid line: {line}"),
        };
        let mut hash_bytes = [0u8; 20];
        hex::decode_to_slice(hash, &mut hash_bytes)
            .with_context(|| format!("Invalid line: {line}"))?;

        let found_hash = file_sha1(
            &mut File::open(file_name)
                .with_context(|| format!("Failed to open file '{file_name}'"))?,
        )?;
        if hash_bytes == found_hash.as_ref() {
            if !args.quiet {
                println!(
                    "{}: {}",
                    file_name,
                    "OK".if_supports_color(Stream::Stdout, |t| t.green())
                );
            }
            matches += 1;
        } else {
            println!("{}: {}", file_name, "FAILED".if_supports_color(Stream::Stdout, |t| t.red()));
            mismatches += 1;
        }
    }
    if args.quiet && matches > 0 {
        println!("{} files {}", matches, "OK".if_supports_color(Stream::Stdout, |t| t.green()));
    }
    if mismatches != 0 {
        eprintln!(
            "{}",
            format!("WARNING: {mismatches} computed checksum(s) did NOT match")
                .if_supports_color(Stream::Stdout, |t| t.yellow())
        );
        std::process::exit(1);
    }
    Ok(())
}

fn hash<R, W>(w: &mut W, reader: &mut R, path: &Utf8NativePath) -> Result<()>
where
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let hash = file_sha1(reader)?;
    let mut hash_buf = [0u8; 40];
    let hash_str = base16ct::lower::encode_str(&hash, &mut hash_buf)
        .map_err(|e| anyhow!("Failed to encode hash: {e}"))?;
    writeln!(w, "{}  {}", hash_str, path.with_unix_encoding())?;
    Ok(())
}

pub fn file_sha1<R>(reader: &mut R) -> Result<sha1::digest::Output<Sha1>>
where R: Read + ?Sized {
    let mut buf = [0u8; DEFAULT_BUF_SIZE];
    let mut hasher = Sha1::new();
    Ok(loop {
        let read = reader.read(&mut buf).context("File read failed")?;
        if read == 0 {
            break hasher.finalize();
        }
        hasher.update(&buf[0..read]);
    })
}

pub fn file_sha1_string<R>(reader: &mut R) -> Result<String>
where R: Read + ?Sized {
    let hash = file_sha1(reader)?;
    let mut hash_buf = [0u8; 40];
    let hash_str = base16ct::lower::encode_str(&hash, &mut hash_buf)
        .map_err(|e| anyhow!("Failed to encode hash: {e}"))?;
    Ok(hash_str.to_string())
}
