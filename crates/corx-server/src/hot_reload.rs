//! SIGHUP-driven configuration hot-reload.
//!
//! The watcher runs as a background tokio task spawned from `serve()` and
//! lives for the duration of the process. On each SIGHUP it:
//!
//! 1. Re-reads the configuration from the same path the operator specified
//!    on startup (or the discovery default when `--config` was omitted).
//! 2. Rejects the reload if any *immutable* field changed (bind address,
//!    TLS material, body limits, request timeout, metrics endpoint). These
//!    are baked into the listener / router and cannot change without a
//!    process restart.
//! 3. Builds a fresh [`LivePolicies`] snapshot from the new config and
//!    atomically swaps it into the [`ServerBuild`]'s `ArcSwap`.
//! 4. Increments `corx_config_reload_total{result}` so dashboards and
//!    alerts can tell apart `ok`, `rejected` (validation / immutable
//!    diff), and `error` (I/O).
//!
//! The watcher is Unix-only because Windows does not deliver SIGHUP; on
//! Windows the binary builds without this module's tasks ever spawning.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use corx_core::config::{Config, ServerConfig, TlsConfig};
#[cfg(unix)]
use corx_core::observability::CONFIG_RELOAD;

use crate::config_loader;
use crate::state::{LivePolicies, ServerBuild};

/// Cheap, `Send`-able handle into a running server's mutable state.
///
/// Cloned into the SIGHUP watcher so the watcher can swap policies without
/// holding a reference to the full [`ServerBuild`].
#[derive(Clone, Debug)]
pub struct ReloadHandle {
    policies: Arc<ArcSwap<LivePolicies>>,
    immutable_server: Arc<ServerConfig>,
    immutable_metrics_endpoint: String,
    immutable_max_body_bytes: u64,
    immutable_request_timeout: std::time::Duration,
}

impl ReloadHandle {
    /// Resolves a fresh configuration from `path`, validates that it
    /// preserves every immutable field, and atomically swaps the policy
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration cannot be loaded, fails
    /// validation, or attempts to mutate an immutable field. The current
    /// snapshot is left untouched on every error path.
    pub fn reload(&self, path: Option<&Path>) -> anyhow::Result<()> {
        let config = config_loader::load(path)?;
        self.assert_immutable(&config)?;
        let policies = LivePolicies::build(config)?;
        self.policies.store(Arc::new(policies));
        Ok(())
    }

    fn assert_immutable(&self, new: &Config) -> anyhow::Result<()> {
        let new_server = &new.server;
        let frozen = self.immutable_server.as_ref();
        if new_server.bind != frozen.bind {
            anyhow::bail!(
                "server.bind cannot be changed by reload (was {}, requested {})",
                frozen.bind,
                new_server.bind
            );
        }
        if new_server.http2 != frozen.http2 {
            anyhow::bail!("server.http2 cannot be changed by reload");
        }
        if !tls_eq(new_server.tls.as_ref(), frozen.tls.as_ref()) {
            anyhow::bail!("server.tls cannot be changed by reload");
        }
        if new.limits.max_request_body_bytes != self.immutable_max_body_bytes {
            anyhow::bail!("limits.max_request_body_bytes cannot be changed by reload");
        }
        if new.limits.request_timeout != self.immutable_request_timeout {
            anyhow::bail!("limits.request_timeout cannot be changed by reload");
        }
        if new.observability.metrics_endpoint != self.immutable_metrics_endpoint {
            anyhow::bail!("observability.metrics_endpoint cannot be changed by reload");
        }
        Ok(())
    }
}

/// Field-wise TLS comparison. `TlsConfig` cannot derive `PartialEq` because
/// it is not part of its public contract (the operator might extend it
/// with non-comparable fields), so we keep the comparison local to the
/// reload guard.
fn tls_eq(a: Option<&TlsConfig>, b: Option<&TlsConfig>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            x.cert_path == y.cert_path
                && x.key_path == y.key_path
                && x.client_ca_path == y.client_ca_path
                && x.alpn_protocols == y.alpn_protocols
        }
        _ => false,
    }
}

impl ServerBuild {
    /// Cheap clone-able reload handle suitable for SIGHUP / API-driven
    /// reload paths.
    #[must_use]
    pub fn hot_reload(&self) -> ReloadHandle {
        ReloadHandle {
            policies: Arc::clone(&self.policies),
            immutable_server: Arc::clone(&self.immutable_server),
            immutable_metrics_endpoint: self.immutable_metrics_endpoint.clone(),
            immutable_max_body_bytes: self.immutable_limits.max_request_body_bytes,
            immutable_request_timeout: self.immutable_limits.request_timeout,
        }
    }
}

/// Loop forever, reloading the configuration on every SIGHUP. Returns
/// when the SIGHUP source closes (process shutdown).
#[cfg(unix)]
pub async fn watch_sighup(path: Option<PathBuf>, handle: ReloadHandle) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hup = match signal(SignalKind::hangup()) {
        Ok(sig) => sig,
        Err(err) => {
            tracing::error!(error = %err, "failed to install SIGHUP handler; hot-reload disabled");
            return;
        }
    };

    while hup.recv().await.is_some() {
        let path_ref = path.as_deref();
        match handle.reload(path_ref) {
            Ok(()) => {
                metrics::counter!(CONFIG_RELOAD, "result" => "ok").increment(1);
                tracing::info!(
                    path = path_ref.and_then(Path::to_str).unwrap_or("<auto>"),
                    "configuration reloaded",
                );
            }
            Err(err) => {
                let result = if err.to_string().contains("cannot be changed by reload") {
                    "rejected"
                } else {
                    "error"
                };
                metrics::counter!(CONFIG_RELOAD, "result" => result).increment(1);
                tracing::warn!(
                    error = %err,
                    path = path_ref.and_then(Path::to_str).unwrap_or("<auto>"),
                    "configuration reload failed; previous snapshot still active",
                );
            }
        }
    }
}

/// No-op stub for non-Unix targets where SIGHUP does not exist.
#[cfg(not(unix))]
#[allow(
    clippy::unused_async,
    reason = "Signature matches the Unix implementation so callers compile uniformly."
)]
pub async fn watch_sighup(_path: Option<PathBuf>, _handle: ReloadHandle) {}

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use std::time::Duration;

    use corx_core::config::Config;

    use super::*;

    /// `LivePolicies::build` instantiates an [`Upstream`] which in turn
    /// drives `hyper-rustls`. rustls panics if no default crypto provider
    /// has been installed, so each test ensures one is set exactly once.
    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // The provider may already have been installed by an earlier
            // test; either outcome is acceptable so we explicitly discard
            // the `Result` to satisfy `let_underscore_must_use`.
            drop(rustls::crypto::ring::default_provider().install_default());
        });
    }

    fn make_handle() -> (ReloadHandle, Config) {
        ensure_crypto_provider();

        let config = Config::default();
        let immutable_server = Arc::new(config.server.clone());
        let immutable_metrics_endpoint = config.observability.metrics_endpoint.clone();
        let immutable_max_body_bytes = config.limits.max_request_body_bytes;
        let immutable_request_timeout = config.limits.request_timeout;

        let policies = LivePolicies::build(config.clone()).expect("policies build");
        let handle = ReloadHandle {
            policies: Arc::new(ArcSwap::from_pointee(policies)),
            immutable_server,
            immutable_metrics_endpoint,
            immutable_max_body_bytes,
            immutable_request_timeout,
        };
        (handle, config)
    }

    #[test]
    fn assert_immutable_accepts_unchanged_config() {
        let (handle, original) = make_handle();
        handle
            .assert_immutable(&original)
            .expect("identical config should pass immutable check");
    }

    #[test]
    fn assert_immutable_rejects_bind_change() {
        let (handle, mut next) = make_handle();
        next.server.bind = "127.0.0.1:31415".parse().unwrap();
        let err = handle
            .assert_immutable(&next)
            .expect_err("bind change must be rejected");
        assert!(err.to_string().contains("server.bind"));
    }

    #[test]
    fn assert_immutable_rejects_request_timeout_change() {
        let (handle, mut next) = make_handle();
        next.limits.request_timeout = Duration::from_secs(123);
        let err = handle
            .assert_immutable(&next)
            .expect_err("request_timeout change must be rejected");
        assert!(err.to_string().contains("limits.request_timeout"));
    }

    #[test]
    fn assert_immutable_accepts_mutable_field_change() {
        let (handle, mut next) = make_handle();
        // `forwarded.inject` is hot-swappable; flipping it must not be
        // flagged as an immutable diff.
        next.forwarded.inject = !next.forwarded.inject;
        handle
            .assert_immutable(&next)
            .expect("mutable field change should pass");
    }

    #[test]
    fn tls_eq_compares_field_wise() {
        assert!(tls_eq(None, None));
        let cfg_a = TlsConfig {
            cert_path: "/a.pem".into(),
            key_path: "/a.key".into(),
            client_ca_path: None,
            alpn_protocols: vec!["h2".into()],
        };
        let cfg_b = cfg_a.clone();
        assert!(tls_eq(Some(&cfg_a), Some(&cfg_b)));
        let cfg_c = TlsConfig {
            alpn_protocols: vec!["http/1.1".into()],
            ..cfg_a.clone()
        };
        assert!(!tls_eq(Some(&cfg_a), Some(&cfg_c)));
        assert!(!tls_eq(Some(&cfg_a), None));
    }
}
