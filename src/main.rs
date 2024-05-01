use std::{env, ffi::OsStr, fmt::Display, path::PathBuf, process::exit, str::FromStr};

use anyhow::Error;
use argp::{FromArgValue, FromArgs};
use enable_ansi_support::enable_ansi_support;
use supports_color::Stream;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

pub mod analysis;
pub mod argp_version;
pub mod cmd;
pub mod obj;
pub mod util;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return Err(()),
        })
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        })
    }
}

impl FromArgValue for LogLevel {
    fn from_arg_value(value: &OsStr) -> Result<Self, String> {
        String::from_arg_value(value)
            .and_then(|s| Self::from_str(&s).map_err(|_| "Invalid log level".to_string()))
    }
}

#[derive(FromArgs, PartialEq, Debug)]
/// Yet another GameCube/Wii decompilation toolkit.
struct TopLevel {
    #[argp(subcommand)]
    command: SubCommand,
    #[argp(option, short = 'C')]
    /// Change working directory.
    chdir: Option<PathBuf>,
    #[argp(option, short = 'L')]
    /// Minimum logging level. (Default: info)
    /// Possible values: error, warn, info, debug, trace
    log_level: Option<LogLevel>,
    /// Print version information and exit.
    #[argp(switch, short = 'V')]
    version: bool,
    /// Disable color output. (env: NO_COLOR)
    #[argp(switch)]
    no_color: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Alf(cmd::alf::Args),
    Ar(cmd::ar::Args),
    Demangle(cmd::demangle::Args),
    Dol(cmd::dol::Args),
    Dwarf(cmd::dwarf::Args),
    Elf(cmd::elf::Args),
    Elf2Dol(cmd::elf2dol::Args),
    Map(cmd::map::Args),
    MetroidBuildInfo(cmd::metroidbuildinfo::Args),
    Nlzss(cmd::nlzss::Args),
    Rarc(cmd::rarc::Args),
    Rel(cmd::rel::Args),
    Rso(cmd::rso::Args),
    Shasum(cmd::shasum::Args),
    Yay0(cmd::yay0::Args),
    Yaz0(cmd::yaz0::Args),
}

// Duplicated from supports-color so we can check early.
fn env_no_color() -> bool {
    match env::var("NO_COLOR").as_deref() {
        Ok("") | Ok("0") | Err(_) => false,
        Ok(_) => true,
    }
}

fn main() {
    let args: TopLevel = argp_version::from_env();
    let use_colors = if args.no_color || env_no_color() {
        false
    } else {
        // Try to enable ANSI support on Windows.
        let _ = enable_ansi_support();
        // Disable isatty check for supports-color. (e.g. when used with ninja)
        env::set_var("IGNORE_IS_TERMINAL", "1");
        supports_color::on(Stream::Stdout).is_some_and(|c| c.has_basic)
    };
    // owo-colors uses an old version of supports-color, so we need to override manually.
    // Ideally, we'd be able to remove the old version of supports-color, but disabling the feature
    // in owo-colors removes set_override and if_supports_color entirely.
    owo_colors::set_override(use_colors);

    let format =
        tracing_subscriber::fmt::format().with_ansi(use_colors).with_target(false).without_time();
    let builder = tracing_subscriber::fmt().event_format(format);
    if let Some(level) = args.log_level {
        builder
            .with_max_level(match level {
                LogLevel::Error => LevelFilter::ERROR,
                LogLevel::Warn => LevelFilter::WARN,
                LogLevel::Info => LevelFilter::INFO,
                LogLevel::Debug => LevelFilter::DEBUG,
                LogLevel::Trace => LevelFilter::TRACE,
            })
            .init();
    } else {
        builder
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }

    let mut result = Ok(());
    if let Some(dir) = &args.chdir {
        result = env::set_current_dir(dir).map_err(|e| {
            Error::new(e)
                .context(format!("Failed to change working directory to '{}'", dir.display()))
        });
    }
    result = result.and_then(|_| match args.command {
        SubCommand::Alf(c_args) => cmd::alf::run(c_args),
        SubCommand::Ar(c_args) => cmd::ar::run(c_args),
        SubCommand::Demangle(c_args) => cmd::demangle::run(c_args),
        SubCommand::Dol(c_args) => cmd::dol::run(c_args),
        SubCommand::Dwarf(c_args) => cmd::dwarf::run(c_args),
        SubCommand::Elf(c_args) => cmd::elf::run(c_args),
        SubCommand::Elf2Dol(c_args) => cmd::elf2dol::run(c_args),
        SubCommand::Map(c_args) => cmd::map::run(c_args),
        SubCommand::MetroidBuildInfo(c_args) => cmd::metroidbuildinfo::run(c_args),
        SubCommand::Nlzss(c_args) => cmd::nlzss::run(c_args),
        SubCommand::Rarc(c_args) => cmd::rarc::run(c_args),
        SubCommand::Rel(c_args) => cmd::rel::run(c_args),
        SubCommand::Rso(c_args) => cmd::rso::run(c_args),
        SubCommand::Shasum(c_args) => cmd::shasum::run(c_args),
        SubCommand::Yay0(c_args) => cmd::yay0::run(c_args),
        SubCommand::Yaz0(c_args) => cmd::yaz0::run(c_args),
    });
    if let Err(e) = result {
        eprintln!("Failed: {e:?}");
        exit(1);
    }
}
