//! TLS / mTLS termination for the inbound listener.
//!
//! Compiled in only when the `tls` Cargo feature is on. Building a
//! [`rustls::ServerConfig`] reads the certificate chain and private key from
//! disk, configures ALPN per the operator's preferences, and — when the
//! `mtls` feature is on and `client_ca_path` is set — requires every
//! incoming connection to present a certificate signed by the configured
//! trust anchors.
//!
//! Serving uses [`axum_server`] which wraps `hyper-util`'s auto-detecting
//! HTTP/1 + HTTP/2 connection builder, exposes `ConnectInfo<SocketAddr>` to
//! handlers, and integrates with the same graceful shutdown signal as the
//! cleartext listener in [`crate::shutdown`].

use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

use corx_core::config::{ServerConfig as ProxyServerConfig, TlsConfig};

/// Compile a [`rustls::ServerConfig`] from the operator-provided settings.
///
/// # Errors
///
/// Returns an error if the certificate chain or key cannot be read or
/// parsed, if the ALPN list is malformed, or \u2014 when an mTLS trust anchor
/// path is supplied \u2014 if its certificates fail to load.
pub fn build_server_config(cfg: &TlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_chain = load_certs(&cfg.cert_path).with_context(|| {
        format!("loading certificate chain from {}", cfg.cert_path.display())
    })?;
    let key = load_private_key(&cfg.key_path)
        .with_context(|| format!("loading private key from {}", cfg.key_path.display()))?;

    let builder = ServerConfig::builder();

    let mut server_config = match (&cfg.client_ca_path, cfg!(feature = "mtls")) {
        (Some(_path), false) => {
            anyhow::bail!(
                "tls.client_ca_path is set but the binary was built without the `mtls` feature"
            );
        }
        #[cfg(feature = "mtls")]
        (Some(path), true) => {
            let roots = load_client_roots(path)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|err| anyhow::anyhow!("building mTLS verifier failed: {err}"))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, key)
                .map_err(|err| anyhow::anyhow!("with_single_cert failed: {err}"))?
        }
        (None, _) => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|err| anyhow::anyhow!("with_single_cert failed: {err}"))?,
    };

    server_config.alpn_protocols = cfg
        .alpn_protocols
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();

    Ok(Arc::new(server_config))
}

#[cfg(feature = "mtls")]
fn load_client_roots(path: &Path) -> anyhow::Result<rustls::RootCertStore> {
    let certs = load_certs(path)
        .with_context(|| format!("loading mTLS root CAs from {}", path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| anyhow::anyhow!("trust anchor rejected: {err}"))?;
    }
    if roots.is_empty() {
        anyhow::bail!("mTLS trust anchor file produced zero usable certificates");
    }
    Ok(roots)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let chain: Vec<CertificateDer<'static>> = certs(&mut reader).collect::<Result<_, _>>()?;
    if chain.is_empty() {
        anyhow::bail!(
            "no PEM-encoded certificates found in {}",
            path.display()
        );
    }
    Ok(chain)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    private_key(&mut reader)?.ok_or_else(|| {
        anyhow::anyhow!("no PEM-encoded private key found in {}", path.display())
    })
}

/// Bind to `cfg.bind`, terminate TLS in-process, and serve `router` over
/// HTTP/1 + HTTP/2 (auto-negotiated via ALPN) until `shutdown` resolves.
///
/// # Errors
///
/// Returns an error if the listener cannot be bound or the TLS configuration
/// cannot be compiled. Per-connection errors are logged by `axum_server`
/// and do not propagate.
pub async fn serve_tls<F>(
    cfg: &ProxyServerConfig,
    tls_cfg: &TlsConfig,
    router: Router<()>,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let server_config = build_server_config(tls_cfg)?;
    let rustls = RustlsConfig::from_config(server_config);

    let handle = Handle::new();
    spawn_shutdown_listener(handle.clone(), cfg.graceful_shutdown, shutdown);

    tracing::info!(address = %cfg.bind, "corx listening (tls)");
    axum_server::bind_rustls(cfg.bind, rustls)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    tracing::info!("tls drain complete");
    Ok(())
}

fn spawn_shutdown_listener<F>(handle: Handle, grace: std::time::Duration, shutdown: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        shutdown.await;
        tracing::info!("shutdown signal received, draining tls connections");
        handle.graceful_shutdown(Some(grace));
    });
}
