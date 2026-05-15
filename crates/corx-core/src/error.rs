//! Unified error taxonomy for the proxy hot path.
//!
//! Each variant carries a stable machine-readable [`ErrorKind`] which is
//! surfaced in the `X-Corx-Status` response header as well as the structured
//! JSON error body. The HTTP status code is derived solely from the kind so
//! that operators can rely on it for alerting.
//!
//! This module is intentionally framework-agnostic: it produces a neutral
//! [`ErrorPayload`] that the surrounding HTTP stack can render into the
//! shape it expects. The `corx-server` crate provides an `axum::IntoResponse`
//! adapter on top of this payload.

use std::io;
use std::net::IpAddr;

use http::StatusCode;
use http::header::HeaderName;
use serde::Serialize;

/// Header name used to expose the machine-readable error kind.
pub const STATUS_HEADER: HeaderName = HeaderName::from_static("x-corx-status");

/// Stable machine-readable identifier for a failure mode.
///
/// Values are kebab-case snake-style so they can be used directly as metric
/// labels and as values of the `X-Corx-Status` header.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The target URL could not be parsed or violates policy.
    InvalidUrl,
    /// The request is missing a required header (e.g. `Origin`).
    MissingRequiredHeader,
    /// The `Origin` header is not allowed by configured policy.
    OriginNotAllowed,
    /// The target host resolves to a blocked IP range (SSRF).
    SsrfBlocked,
    /// The target hostname could not be resolved via DNS.
    DnsFailure,
    /// The upstream connection was refused or reset.
    UpstreamUnreachable,
    /// The upstream request timed out.
    UpstreamTimeout,
    /// The upstream returned too many redirect hops.
    TooManyRedirects,
    /// A TLS handshake with the upstream failed.
    TlsFailure,
    /// The request payload exceeded the configured limit.
    PayloadTooLarge,
    /// The client exceeded its rate limit budget.
    RateLimited,
    /// A server-side I/O error occurred.
    Io,
    /// An uncategorised internal error.
    Internal,
}

impl ErrorKind {
    /// Maps the kind onto the HTTP status code returned to the client.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidUrl | Self::MissingRequiredHeader => StatusCode::BAD_REQUEST,
            Self::OriginNotAllowed | Self::SsrfBlocked => StatusCode::FORBIDDEN,
            Self::DnsFailure | Self::UpstreamUnreachable | Self::TlsFailure => {
                StatusCode::BAD_GATEWAY
            }
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::TooManyRedirects => StatusCode::LOOP_DETECTED,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Io | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Machine-readable identifier as exposed on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::MissingRequiredHeader => "missing_required_header",
            Self::OriginNotAllowed => "origin_not_allowed",
            Self::SsrfBlocked => "ssrf_blocked",
            Self::DnsFailure => "dns_failure",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::TooManyRedirects => "too_many_redirects",
            Self::TlsFailure => "tls_failure",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::Io => "io",
            Self::Internal => "internal",
        }
    }
}

/// Top-level proxy error type returned from handlers and middleware.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The target URL is malformed, uses an unsupported scheme, or is missing
    /// required components.
    #[error("invalid target url: {0}")]
    InvalidUrl(String),

    /// The inbound request is missing a header that the operator requires.
    #[error("missing required header: `{0}`")]
    MissingHeader(&'static str),

    /// The inbound `Origin` is not allowed by the configured policy.
    #[error("origin `{0}` is not allowed")]
    OriginNotAllowed(String),

    /// The resolved target address is within a blocked CIDR range.
    #[error("target resolves to blocked address: {0}")]
    SsrfBlocked(IpAddr),

    /// DNS resolution failed for the target host.
    #[error("dns lookup failed for `{host}`: {source}")]
    Dns {
        /// The hostname that was being resolved.
        host: String,
        /// Underlying resolver error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The upstream server could not be reached.
    #[error("upstream unreachable: {0}")]
    Upstream(Box<dyn std::error::Error + Send + Sync>),

    /// A request to the upstream timed out.
    #[error("upstream timed out")]
    UpstreamTimeout,

    /// Exceeded the configured redirect budget.
    #[error("too many redirects (limit {0})")]
    TooManyRedirects(u8),

    /// TLS handshake with upstream failed.
    #[error("tls handshake failed: {0}")]
    Tls(Box<dyn std::error::Error + Send + Sync>),

    /// The request or response body exceeded configured limits.
    #[error("payload too large")]
    PayloadTooLarge,

    /// The request was rate-limited.
    #[error("rate limited")]
    RateLimited,

    /// Low-level I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Any other uncategorised failure.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl ProxyError {
    /// Classifies the error into a stable [`ErrorKind`] for wire exposure.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidUrl(_) => ErrorKind::InvalidUrl,
            Self::MissingHeader(_) => ErrorKind::MissingRequiredHeader,
            Self::OriginNotAllowed(_) => ErrorKind::OriginNotAllowed,
            Self::SsrfBlocked(_) => ErrorKind::SsrfBlocked,
            Self::Dns { .. } => ErrorKind::DnsFailure,
            Self::Upstream(_) => ErrorKind::UpstreamUnreachable,
            Self::UpstreamTimeout => ErrorKind::UpstreamTimeout,
            Self::TooManyRedirects(_) => ErrorKind::TooManyRedirects,
            Self::Tls(_) => ErrorKind::TlsFailure,
            Self::PayloadTooLarge => ErrorKind::PayloadTooLarge,
            Self::RateLimited => ErrorKind::RateLimited,
            Self::Io(_) => ErrorKind::Io,
            Self::Internal(_) => ErrorKind::Internal,
        }
    }
}

/// Neutral, framework-agnostic representation of a proxy error response.
///
/// HTTP layer adapters (e.g. `corx-server`) consume this to render an actual
/// response in whatever shape their framework expects.
#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    /// Machine-readable identifier, identical to [`ErrorKind::as_str`].
    pub error: &'static str,
    /// Human-readable detail; safe to expose to clients.
    pub message: String,
}

impl ProxyError {
    /// Renders the error into the wire-level pieces required to construct a
    /// HTTP response: status code and the JSON-serialisable payload.
    ///
    /// Adapters typically:
    ///
    /// 1. Set the response status to `payload.0`.
    /// 2. Insert `X-Corx-Status: <payload.1.error>` into the headers.
    /// 3. Serialise `payload.1` as JSON.
    /// 4. Apply the active CORS policy on top so the client browser can read it.
    #[must_use]
    pub fn to_payload(&self) -> (StatusCode, ErrorPayload) {
        let kind = self.kind();
        (
            kind.status(),
            ErrorPayload {
                error: kind.as_str(),
                message: self.to_string(),
            },
        )
    }
}
