use std::path::PathBuf;

use anyhow::{anyhow, Result};
use argp::FromArgs;

use crate::{
    util::rarc::{RarcNodeKind, RarcView},
    vfs::open_path,
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
    let mut file = open_path(&args.file, true)?;
    let view = RarcView::new(file.map()?).map_err(|e| anyhow!(e))?;
    test(&view, "")?;
    test(&view, "/")?;
    test(&view, "//")?;
    test(&view, "/rels")?;
    test(&view, "/rels/")?;
    test(&view, "/rels/amem")?;
    test(&view, "/rels/amem/")?;
    test(&view, "/rels/mmem")?;
    test(&view, "/rels/mmem/../mmem")?;
    test(&view, "/rels/amem/d_a_am.rel")?;
    test(&view, "//amem/d_a_am.rel")?;
    test(&view, "amem/d_a_am.rel")?;
    test(&view, "amem/d_a_am.rel/")?;
    test(&view, "mmem/d_a_obj_pirateship.rel")?;
    test(&view, "mmem//d_a_obj_pirateship.rel")?;
    test(&view, "mmem/da_obj_pirateship.rel")?;
    Ok(())
}

fn test(view: &RarcView, path: &str) -> Result<()> {
    let option = view.find(path);
    let data = if let Some(RarcNodeKind::File(_, node)) = option {
        view.get_data(node).map_err(|e| anyhow!(e))?
    } else {
        &[]
    };
    let vec = data.iter().cloned().take(4).collect::<Vec<_>>();
    println!("{:?}: {:?} (len: {:?})", path, option, vec.as_slice());
    // if let Some(RarcNodeKind::Directory(_, dir)) = option {
    //     for node in view.children(dir) {
    //         println!("Child: {:?} ({:?})", node, view.get_string(node.name_offset()));
    //     }
    // }
    Ok(())
}

fn extract(_args: ExtractArgs) -> Result<()> { todo!() }
