use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read},
    path::Path,
};

use anyhow::{Context, Error, Result};
use argh::FromArgs;
use filetime::{set_file_mtime, FileTime};
use sha1::{Digest, Sha1};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Print or check SHA1 (160-bit) checksums.
#[argh(subcommand, name = "shasum")]
pub struct Args {
    #[argh(switch, short = 'c')]
    /// check SHA sums against given list
    check: bool,
    #[argh(positional)]
    /// path to file
    file: String,
    #[argh(option, short = 'o')]
    /// touch output file on successful check
    output: Option<String>,
}

const DEFAULT_BUF_SIZE: usize = 8192;

pub fn run(args: Args) -> Result<()> {
    let file =
        File::open(&args.file).with_context(|| format!("Failed to open file '{}'", args.file))?;
    if args.check {
        check(args, file)
    } else {
        hash(args, file)
    }
}

fn check(args: Args, file: File) -> Result<()> {
    let reader = BufReader::new(file);
    let mut mismatches = 0usize;
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => return Err(Error::msg(format!("File read failed: {}", e))),
        };
        let (hash, file_name) =
            line.split_once(' ').ok_or_else(|| Error::msg(format!("Invalid line: {}", line)))?;
        let file_name = match file_name.chars().next() {
            Some(' ') | Some('*') => &file_name[1..],
            _ => return Err(Error::msg(format!("Invalid line: {}", line))),
        };
        let mut hash_bytes = [0u8; 20];
        hex::decode_to_slice(hash, &mut hash_bytes)
            .with_context(|| format!("Invalid line: {}", line))?;

        let file = File::open(file_name)
            .with_context(|| format!("Failed to open file '{}'", file_name))?;
        let found_hash = file_sha1(file)?;
        if hash_bytes == found_hash.as_ref() {
            println!("{}: OK", file_name);
        } else {
            println!("{}: FAILED", file_name);
            mismatches += 1;
        }
    }
    if mismatches != 0 {
        eprintln!("WARNING: {} computed checksum did NOT match", mismatches);
        std::process::exit(1);
    }
    if let Some(out_path) = args.output {
        touch(&out_path).with_context(|| format!("Failed to touch output file '{}'", out_path))?;
    }
    Ok(())
}

fn hash(args: Args, file: File) -> Result<()> {
    let hash = file_sha1(file)?;
    let mut hash_buf = [0u8; 40];
    let hash_str = base16ct::lower::encode_str(&hash, &mut hash_buf)
        .map_err(|e| Error::msg(format!("Failed to encode hash: {}", e)))?;
    println!("{}  {}", hash_str, args.file);
    Ok(())
}

fn file_sha1(mut file: File) -> Result<sha1::digest::Output<Sha1>> {
    let mut buf = [0u8; DEFAULT_BUF_SIZE];
    let mut hasher = Sha1::new();
    Ok(loop {
        let read = file.read(&mut buf).context("File read failed")?;
        if read == 0 {
            break hasher.finalize();
        }
        hasher.update(&buf[0..read]);
    })
}

fn touch<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    if path.as_ref().exists() {
        set_file_mtime(path, FileTime::now())
    } else {
        match OpenOptions::new().create(true).write(true).open(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
