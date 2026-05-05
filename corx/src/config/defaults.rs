//! Built-in configuration defaults.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{
    Config, CorsConfig, CorsPolicyKind, LimitsConfig, LogFormat, ObservabilityConfig,
    RateLimitConfig, SecurityConfig, ServerConfig, SsrfConfig, UpstreamConfig,
};

const MIB: u64 = 1024 * 1024;

impl Config {
    /// Returns the out-of-the-box default configuration, suitable for local
    /// development and as the base layer for overrides.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            server: ServerConfig {
                bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
                workers: 0,
                graceful_shutdown: Duration::from_secs(30),
                http2: true,
                tls: None,
            },
            limits: LimitsConfig {
                max_request_body_bytes: 10 * MIB,
                max_request_header_bytes: 32 * 1024,
                request_timeout: Duration::from_mins(1),
                connect_timeout: Duration::from_secs(10),
                max_redirects: 5,
            },
            cors: CorsConfig {
                policy: CorsPolicyKind::Reflect,
                allowlist: Vec::new(),
                explicit: Vec::new(),
                max_age: Duration::from_mins(10),
                allow_credentials: false,
            },
            security: SecurityConfig {
                require_header: vec!["origin".into()],
                block_methods: vec!["CONNECT".into(), "TRACE".into()],
                remove_request_headers: vec!["cookie".into(), "cookie2".into()],
                remove_response_headers: vec!["set-cookie".into(), "set-cookie2".into()],
                origin_blacklist: Vec::new(),
                origin_whitelist: Vec::new(),
            },
            ssrf: SsrfConfig {
                enabled: true,
                extra_blocked_cidrs: Vec::new(),
                allow_ipv6: true,
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                per_origin_rps: 10,
                burst: 20,
                unlimited_hosts: Vec::new(),
            },
            upstream: UpstreamConfig {
                pool_max_idle_per_host: 32,
                pool_idle_timeout: Duration::from_secs(90),
                user_agent: format!("corx/{}", env!("CARGO_PKG_VERSION")),
            },
            observability: ObservabilityConfig {
                log_format: LogFormat::Json,
                log_level: "info".into(),
                metrics_endpoint: "/metrics".into(),
            },
        }
    }
}
