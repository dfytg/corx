//! Server lifecycle: bind, serve, and drain connections gracefully on
//! signal. Switches between cleartext (`axum::serve`) and TLS
//! (`crate::tls::serve_tls`) based on the configuration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use corx_core::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::signal;

/// Binds to the configured socket and serves the supplied router until a
/// shutdown signal is received, then drains in-flight connections within
/// the configured grace period.
///
/// `ready` is flipped to `false` as soon as a shutdown signal arrives so
/// `/readyz` immediately reports `503` and load balancers stop sending new
/// traffic while existing requests drain.
///
/// # Errors
///
/// Returns an error when the listener cannot be bound, the TLS
/// configuration cannot be loaded, or the shutdown handler cannot register
/// a signal listener.
pub async fn run(
    cfg: &ServerConfig,
    router: Router<()>,
    ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    if let Some(tls_cfg) = cfg.tls.as_ref() {
        return run_tls(cfg, tls_cfg, router, ready).await;
    }
    run_plain(cfg, router, ready).await
}

async fn run_plain(
    cfg: &ServerConfig,
    router: Router<()>,
    ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    let local_addr = listener.local_addr().unwrap_or(cfg.bind);
    tracing::info!(address = %local_addr, http2 = cfg.http2, "corx listening");

    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    let grace = cfg.graceful_shutdown;

    // Signal path: flip ready → notify graceful shutdown → wait up to
    // `grace`. If drain finishes first, serve returns Ok; if the deadline
    // fires first, dropping the server aborts remaining connections.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let ready_for_signal = Arc::clone(&ready);

    let server = axum::serve(listener, service).with_graceful_shutdown(async {
        // Receiver is dropped when the signal path has already aborted; either
        // outcome is fine — we only need to wait for the first send.
        match shutdown_rx.await {
            Ok(()) | Err(_) => {}
        }
    });

    tokio::select! {
        result = server => {
            result?;
            tracing::info!("shutdown complete");
        }
        () = async {
            wait_os_signal().await;
            ready_for_signal.store(false, Ordering::Release);
            tracing::info!(
                grace_secs = grace.as_secs_f64(),
                "shutdown signal received, draining connections"
            );
            // Ignore send failure if the server already finished.
            match shutdown_tx.send(()) {
                Ok(()) | Err(()) => {}
            }
            tokio::time::sleep(grace).await;
        } => {
            tracing::warn!(
                grace_secs = grace.as_secs_f64(),
                "graceful shutdown deadline exceeded; aborting remaining connections"
            );
        }
    }

    Ok(())
}

#[cfg(feature = "tls")]
async fn run_tls(
    cfg: &ServerConfig,
    tls_cfg: &corx_core::config::TlsConfig,
    router: Router<()>,
    ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    crate::tls::serve_tls(cfg, tls_cfg, router, shutdown_signal(ready)).await
}

#[cfg(not(feature = "tls"))]
#[allow(
    clippy::unused_async,
    reason = "Signature mirrors the `tls`-feature variant so the calling \
              code path stays identical regardless of build features."
)]
async fn run_tls(
    _cfg: &ServerConfig,
    _tls_cfg: &corx_core::config::TlsConfig,
    _router: Router<()>,
    _ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "server.tls is configured but corx was built without the `tls` feature; \
         rebuild with `--features tls`"
    )
}

/// Resolves once Ctrl+C or SIGTERM (Unix) is received and flips `ready` to
/// `false`. Public so alternative listeners (e.g. the TLS path) can
/// subscribe to the same signal source.
pub async fn shutdown_signal(ready: Arc<AtomicBool>) {
    wait_os_signal().await;
    ready.store(false, Ordering::Release);
    tracing::info!("shutdown signal received, draining connections");
}

/// Blocks until Ctrl+C or SIGTERM without mutating readiness.
async fn wait_os_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => tracing::error!(error = %err, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
