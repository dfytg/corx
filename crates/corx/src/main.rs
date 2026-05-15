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

// Transitive workspace dependencies pulled in via features are not directly
// named here; silence the `unused_crate_dependencies` lint for those entries.
#![allow(
    unused_crate_dependencies,
    reason = "binary only uses the corx-core / corx-server re-exports"
)]

mod cli;

use clap::Parser as _;
use corx_server::config_loader;
use corx_server::observability::{init_metrics, init_tracing};
use corx_server::{AppState, ServerBuild, build_router, run};

use crate::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run_app(cli).await
}

async fn run_app(cli: Cli) -> anyhow::Result<()> {
    install_crypto_provider();

    let config = config_loader::load(cli.config.as_deref())?;
    init_tracing(&config.observability)?;
    let metrics = init_metrics()?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "corx starting"
    );

    let build = ServerBuild::from_config(config.clone(), metrics)?;
    let ready = build.ready.clone();
    let router = build_router(AppState::new(build));

    run(&config.server, router, ready).await
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
