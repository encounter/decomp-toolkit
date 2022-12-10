// From https://gist.github.com/suluke/e0c672492126be0a4f3b4f0e1115d77c
//! Extend `argh` to be better integrated with the `cargo` ecosystem
//!
//! For now, this only adds a --version/-V option which causes early-exit.
use argh::{FromArgs, TopLevelCommand};

struct ArgsOrVersion<T: FromArgs>(T);
impl<T> TopLevelCommand for ArgsOrVersion<T> where T: FromArgs {}
impl<T> FromArgs for ArgsOrVersion<T>
where T: FromArgs
{
    fn from_args(command_name: &[&str], args: &[&str]) -> Result<Self, argh::EarlyExit> {
        /// Also use argh for catching `--version`-only invocations
        #[derive(FromArgs)]
        struct Version {
            /// print version information and exit
            #[argh(switch, short = 'V')]
            pub version: bool,
        }
        match Version::from_args(command_name, args) {
            Ok(v) => {
                if v.version {
                    Err(argh::EarlyExit {
                        output: format!(
                            "{} {} {}",
                            command_name.first().unwrap_or(&""),
                            env!("VERGEN_BUILD_SEMVER"),
                            env!("VERGEN_GIT_SHA"),
                        ),
                        status: Ok(()),
                    })
                } else {
                    // seems args are empty
                    T::from_args(command_name, args).map(Self)
                }
            }
            Err(exit) => match exit.status {
                Ok(()) => {
                    // must have been --help
                    let help = match T::from_args(command_name, &["--help"]) {
                        Ok(_) => unreachable!(),
                        Err(exit) => exit.output,
                    };
                    Err(argh::EarlyExit {
                        output: format!(
                            "{help}  -V, --version     print version information and exit"
                        ),
                        status: Ok(()),
                    })
                }
                Err(()) => T::from_args(command_name, args).map(Self),
            },
        }
    }
}

/// Create a `FromArgs` type from the current process’s `env::args`.
///
/// This function will exit early from the current process if argument parsing was unsuccessful or if information like `--help` was requested.
/// Error messages will be printed to stderr, and `--help` output to stdout.
pub fn from_env<T>() -> T
where T: TopLevelCommand {
    argh::from_env::<ArgsOrVersion<T>>().0
}
