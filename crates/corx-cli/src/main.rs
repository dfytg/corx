//! `corx` CLI entry point (crate `corx-cli`).
//!
//! Responsibilities:
//!
//! 1. Parse CLI arguments.
//! 2. Load layered configuration.
//! 3. Install the `rustls` default crypto provider.
//! 4. Initialise the `tracing` subscriber and Prometheus recorder.
//! 5. Assemble proxy dependencies via the [`corx`] umbrella library.
//! 6. Bind the HTTP listener and serve until a shutdown signal arrives.

#![allow(
    unused_crate_dependencies,
    clippy::print_stdout,
    reason = "Transitive workspace dependencies pulled in via features are \
              not directly named here; the binary uses the corx umbrella \
              re-exports. CLI subcommands print to stdout by design."
)]

mod cli;

use std::path::Path;

use clap::Parser as _;
use corx::Config;
use corx::server::config_loader;
use corx::server::observability::{active_features, init_metrics, init_tracing};
use corx::{AppState, ServerBuild, build_router, run};

use crate::cli::{Cli, Command, DumpFormat};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.as_deref();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config_path).await,
        Command::Check => check(config_path),
        Command::Dump { format } => dump(config_path, format),
        Command::Version => {
            print_version();
            Ok(())
        }
    }
}

async fn serve(config_path: Option<&Path>) -> anyhow::Result<()> {
    install_crypto_provider();

    let config = config_loader::load(config_path)?;
    init_tracing(&config.observability)?;
    let metrics = init_metrics()?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "corx starting"
    );

    let build = ServerBuild::from_config(config.clone(), metrics)?;
    let ready = std::sync::Arc::clone(&build.ready);

    // Hot-reload watcher (Unix only): SIGHUP triggers a fresh load of the
    // same config path. Hot-swappable fields are atomically replaced via
    // `arc-swap`; immutable fields (bind address, TLS material) only log a
    // warning and are otherwise ignored. The watcher exits with the
    // server.
    #[cfg(unix)]
    {
        let owned_path = config_path.map(Path::to_path_buf);
        let reload_handle = build.hot_reload();
        tokio::spawn(async move {
            corx::server::hot_reload::watch_sighup(owned_path, reload_handle).await;
        });
    }

    let router = build_router(AppState::new(build));
    run(&config.server, router, ready).await
}

fn check(config_path: Option<&Path>) -> anyhow::Result<()> {
    let config = config_loader::load(config_path)?;
    println!(
        "config OK \u{2014} bind = {}, tls = {}, ssrf = {:?}",
        config.server.bind,
        if config.server.tls.is_some() {
            "on"
        } else {
            "off"
        },
        config.ssrf.mode
    );
    Ok(())
}

fn dump(config_path: Option<&Path>, format: DumpFormat) -> anyhow::Result<()> {
    let config = config_loader::load(config_path)?;
    let rendered = match format {
        DumpFormat::Toml => render_toml(&config)?,
        DumpFormat::Json => serde_json::to_string_pretty(&config)?,
    };
    println!("{rendered}");
    Ok(())
}

fn render_toml(config: &Config) -> anyhow::Result<String> {
    Ok(toml::to_string_pretty(config)?)
}

fn print_version() {
    println!(
        "corx {version} ({os}/{arch}) features={features}",
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        features = active_features(),
    );
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
