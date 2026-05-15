//! Built-in configuration defaults.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{
    Config, CorsConfig, CorsPolicyKind, ForwardedConfig, LimitsConfig, LogFormat,
    ObservabilityConfig, RateLimitConfig, SecurityConfig, ServerConfig, SsrfConfig, SsrfMode,
    UpstreamConfig,
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
                allow_https_to_http_downgrade: false,
            },
            cors: CorsConfig {
                policy: CorsPolicyKind::Reflect,
                allowlist: Vec::new(),
                explicit: Vec::new(),
                allowed_methods: super::default_allowed_methods(),
                allowed_headers: super::default_allowed_headers(),
                exposed_headers: super::default_exposed_headers(),
                max_age: Duration::from_mins(10),
                allow_credentials: false,
                allow_private_network: false,
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
                mode: SsrfMode::Strict,
                allow_ipv6: true,
                extra_blocked_cidrs: Vec::new(),
                extra_allowed_cidrs: Vec::new(),
                deny_redirect_to_private: true,
            },
            forwarded: ForwardedConfig::default(),
            rate_limit: RateLimitConfig {
                enabled: false,
                origin: super::OriginLimitConfig {
                    rps: 50,
                    burst: 100,
                    unlimited_patterns: Vec::new(),
                },
                ip: super::IpLimitConfig {
                    rps: 30,
                    burst: 60,
                    trusted_cidrs: Vec::new(),
                },
                target_host: super::HostLimitConfig {
                    rps: 100,
                    burst: 200,
                },
                global: super::GlobalLimitConfig {
                    rps: 5_000,
                    burst: 10_000,
                    inflight_max: 1_000,
                },
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
                otel: super::OtelConfig::default(),
            },
        }
    }
}
