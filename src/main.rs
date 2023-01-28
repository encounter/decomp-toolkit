use argh::FromArgs;

pub mod analysis;
pub mod argh_version;
pub mod cmd;
pub mod obj;
pub mod util;

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
    Dol(cmd::dol::Args),
    Elf(cmd::elf::Args),
    Elf2Dol(cmd::elf2dol::Args),
    Map(cmd::map::Args),
    MetroidBuildInfo(cmd::metroidbuildinfo::Args),
    Rel(cmd::rel::Args),
    Rso(cmd::rso::Args),
    Shasum(cmd::shasum::Args),
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: TopLevel = argh_version::from_env();
    let result = match args.command {
        SubCommand::Ar(c_args) => cmd::ar::run(c_args),
        SubCommand::Demangle(c_args) => cmd::demangle::run(c_args),
        SubCommand::Dol(c_args) => cmd::dol::run(c_args),
        SubCommand::Elf(c_args) => cmd::elf::run(c_args),
        SubCommand::Elf2Dol(c_args) => cmd::elf2dol::run(c_args),
        SubCommand::Map(c_args) => cmd::map::run(c_args),
        SubCommand::MetroidBuildInfo(c_args) => cmd::metroidbuildinfo::run(c_args),
        SubCommand::Rel(c_args) => cmd::rel::run(c_args),
        SubCommand::Rso(c_args) => cmd::rso::run(c_args),
        SubCommand::Shasum(c_args) => cmd::shasum::run(c_args),
    };
    if let Err(e) = result {
        eprintln!("Failed: {e:?}");
        std::process::exit(1);
    }
}
