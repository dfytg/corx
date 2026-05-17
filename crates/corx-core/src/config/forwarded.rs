//! `Forwarded` / `X-Forwarded-*` / `X-Request-Id` injection configuration.

use serde::{Deserialize, Serialize};

/// Configures `Forwarded` / `X-Forwarded-*` / `X-Request-Id` injection.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedConfig {
    /// Stamp `X-Forwarded-*` and RFC 7239 `Forwarded` on outbound requests.
    #[serde(default = "super::default_true")]
    pub inject: bool,
    /// Trust an inbound `X-Forwarded-For` chain and append our peer IP.
    /// Defaults to `false`: an internet-facing deployment must not let a
    /// client poison logs by forging upstream forwarders.
    #[serde(default)]
    pub trust_inbound_xff: bool,
    /// Generate a UUID v7 `X-Request-Id` when the client did not supply one.
    #[serde(default = "super::default_true")]
    pub inject_request_id: bool,
}

impl Default for ForwardedConfig {
    fn default() -> Self {
        Self {
            inject: true,
            trust_inbound_xff: false,
            inject_request_id: true,
        }
    }
}
