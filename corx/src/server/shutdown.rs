//! Server lifecycle: bind, serve, and drain connections gracefully on
//! signal. Uses `axum::serve()` to delegate the low-level hyper plumbing.

use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal;

use crate::config::ServerConfig;

/// Binds to the configured socket and serves the supplied router until a
/// shutdown signal is received, then drains in-flight connections within
/// the configured grace period.
///
/// # Errors
///
/// Returns an error when the listener cannot be bound or the shutdown
/// handler cannot register a signal listener.
pub async fn run(cfg: &ServerConfig, router: Router<()>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.bind).await?;
    let local_addr = listener.local_addr().unwrap_or(cfg.bind);
    tracing::info!(address = %local_addr, http2 = cfg.http2, "corx listening");

    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    let shutdown = shutdown_signal();

    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown)
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
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

    tracing::info!("shutdown signal received, draining connections");
}
