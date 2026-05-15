//! `tracing` subscriber bootstrap.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use corx_core::config::{LogFormat, ObservabilityConfig};

/// Installs the global `tracing` subscriber.
///
/// Call exactly once at process start, before any spans are recorded.
///
/// # Errors
///
/// Returns an error if the subscriber could not be installed (usually because
/// one is already globally registered).
pub fn init_tracing(cfg: &ObservabilityConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&cfg.log_level)
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    match cfg.log_format {
        LogFormat::Json => {
            let layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_ansi(false)
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false);
            registry.with(layer).try_init()?;
        }
        LogFormat::Pretty => {
            let layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_ansi(true)
                .compact();
            registry.with(layer).try_init()?;
        }
    }

    Ok(())
}
