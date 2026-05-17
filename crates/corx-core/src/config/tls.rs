//! TLS configuration for the inbound listener.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// TLS configuration for the inbound listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key (PKCS#8 or RSA).
    pub key_path: PathBuf,
    /// Path to the PEM-encoded trust anchors used to validate client
    /// certificates. When set, the server will require mTLS. Requires the
    /// `mtls` Cargo feature on the binary.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    /// ALPN protocols to advertise, in preference order. Defaults to
    /// `["h2", "http/1.1"]`.
    #[serde(default = "default_alpn_protocols")]
    pub alpn_protocols: Vec<String>,
}

fn default_alpn_protocols() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}
