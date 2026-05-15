//! Command-line interface definition.

use std::path::PathBuf;

use clap::Parser;

/// High-performance CORS forwarding proxy.
#[derive(Debug, Parser)]
#[command(name = "corx", version, about)]
pub(crate) struct Cli {
    /// Path to an override configuration file. Supersedes the built-in
    /// discovery logic (`$CORX_CONFIG`, `./corx.toml`, `/etc/corx/config.toml`).
    #[arg(short = 'c', long = "config", env = "CORX_CONFIG")]
    pub(crate) config: Option<PathBuf>,
}
