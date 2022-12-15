extern crate core;

use argh::FromArgs;

mod argh_version;
mod cmd;
mod util;

#[derive(FromArgs, PartialEq, Debug)]
/// GameCube/Wii decompilation project tools.
struct TopLevel {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Ar(cmd::ar::Args),
    Demangle(cmd::demangle::Args),
    Elf(cmd::elf::Args),
    Elf2Dol(cmd::elf2dol::Args),
    Map(cmd::map::Args),
    MetroidBuildInfo(cmd::metroidbuildinfo::Args),
    Shasum(cmd::shasum::Args),
}

fn main() {
    pretty_env_logger::init();

    let args: TopLevel = argh_version::from_env();
    let result = match args.command {
        SubCommand::Ar(c_args) => cmd::ar::run(c_args),
        SubCommand::Demangle(c_args) => cmd::demangle::run(c_args),
        SubCommand::Elf(c_args) => cmd::elf::run(c_args),
        SubCommand::Elf2Dol(c_args) => cmd::elf2dol::run(c_args),
        SubCommand::Map(c_args) => cmd::map::run(c_args),
        SubCommand::MetroidBuildInfo(c_args) => cmd::metroidbuildinfo::run(c_args),
        SubCommand::Shasum(c_args) => cmd::shasum::run(c_args),
    };
    if let Err(e) = result {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
