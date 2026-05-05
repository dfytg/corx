//! `corx` entry point.
//!
//! Responsibilities:
//!
//! 1. Parse CLI arguments.
//! 2. Load layered configuration.
//! 3. Install the `rustls` default crypto provider.
//! 4. Initialise the `tracing` subscriber and Prometheus recorder.
//! 5. Assemble proxy dependencies.
//! 6. Bind the HTTP listener and serve until a shutdown signal arrives.

// Transitive dependencies required by the library are not directly referenced
// from the binary crate; silence the `unused_crate_dependencies` lint for
// those entries rather than polluting main with `use X as _;` imports.
#![allow(
    unused_crate_dependencies,
    reason = "binary only uses the library re-exports"
)]

use clap::Parser as _;
use corx::cli::Cli;
use corx::config::Config;
use corx::observability::{init_metrics, init_tracing};
use corx::server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    install_crypto_provider();

    let config = Config::load(cli.config.as_deref())?;
    init_tracing(&config.observability)?;
    let metrics = init_metrics()?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "corx starting"
    );

    let build = server::ServerBuild::from_config(config.clone(), metrics)?;
    let router = server::build_router(server::AppState::new(build));

    server::run(&config.server, router).await
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none()
        && rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
    {
        tracing::warn!("rustls default crypto provider was already installed");
    }
}
