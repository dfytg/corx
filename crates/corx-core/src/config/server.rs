//! HTTP listener configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::TlsConfig;

/// HTTP listener configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind the HTTP listener to.
    pub bind: SocketAddr,
    /// Number of Tokio worker threads. `0` selects `num_cpus::get()`.
    pub workers: usize,
    /// How long to wait for in-flight requests during shutdown.
    #[serde(with = "humantime_serde")]
    pub graceful_shutdown: Duration,
    /// Enable HTTP/2 on the inbound listener.
    pub http2: bool,
    /// Optional TLS settings (requires the `tls` cargo feature at compile time).
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            workers: 0,
            graceful_shutdown: Duration::from_secs(30),
            http2: true,
            tls: None,
        }
    }
}
