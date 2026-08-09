//! Command-line interface definition.
//!
//! Surface follows the well-trodden one-subcommand-per-operator-action
//! pattern: `serve` (default if no subcommand is given) runs the proxy,
//! `check` validates the configuration without binding sockets, `dump`
//! emits the fully-resolved configuration as TOML or JSON for diffing
//! against running deployments, and `version` reports the build identity
//! recorded in `Cargo.toml`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// High-performance CORS forwarding proxy.
#[derive(Debug, Parser)]
#[command(name = "corx", version, about, propagate_version = true)]
pub(crate) struct Cli {
    /// Path to an override configuration file. Supersedes the built-in
    /// discovery logic (`$CORX_CONFIG`, `./corx.toml`, `/etc/corx/config.toml`).
    /// Available on every subcommand for consistency.
    #[arg(short = 'c', long = "config", env = "CORX_CONFIG", global = true)]
    pub(crate) config: Option<PathBuf>,

    /// Operator action. Defaults to `serve` when omitted so the bare
    /// `corx` invocation keeps the historical behaviour.
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// Top-level operator actions.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Start the proxy listener and serve traffic until a shutdown signal.
    Serve,
    /// Validate the configuration and exit non-zero if invalid. Useful in
    /// CI / CD pipelines and as a Kubernetes init-container check.
    Check,
    /// Print the fully-resolved (defaulted) configuration to stdout.
    Dump {
        /// Output format.
        #[arg(long, value_enum, default_value_t = DumpFormat::Toml)]
        format: DumpFormat,
    },
    /// Print the build identity (version, target triple, feature set).
    Version,
}

/// Output format for the `dump` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum DumpFormat {
    /// TOML, matching the format of `corx.toml`.
    Toml,
    /// Pretty-printed JSON, useful for `jq` pipelines.
    Json,
}
