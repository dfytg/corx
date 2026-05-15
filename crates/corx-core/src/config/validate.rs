//! Configuration validation.
//!
//! `Config::validate` is run after layered loading (defaults + TOML + env)
//! but before the proxy is started. It rejects combinations that we know
//! are unsafe or non-functional rather than letting them surface as
//! mysterious runtime failures hours later.
//!
//! Every check is fail-closed: a single violation aborts startup with a
//! helpful path-and-reason error so operators can fix the config and
//! retry.

use std::fmt;

use super::{Config, CorsPolicyKind, RateLimitConfig};

/// Configuration error with a stable JSON shape.
///
/// `path` follows dot-notation (`cors.allow_credentials`) so log scrapers
/// can correlate failures across deployments.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("invalid configuration at `{path}`: {reason}")]
pub struct ConfigError {
    /// Dot-separated path inside the configuration tree.
    pub path: String,
    /// Human-readable explanation of why the value is rejected.
    pub reason: String,
}

impl ConfigError {
    fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

/// Aggregated validation outcome. Holds every issue found in a single
/// pass so operators can fix multiple problems per restart.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ValidationReport {
    /// Hard failures that must be fixed before the server can start.
    pub errors: Vec<ConfigError>,
    /// Soft warnings the operator should review but that do not block
    /// startup.
    pub warnings: Vec<ConfigError>,
}

impl ValidationReport {
    /// Returns `true` when there is at least one hard error in the report.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for err in &self.errors {
            writeln!(f, "ERROR {err}")?;
        }
        for warn in &self.warnings {
            writeln!(f, "WARN  {warn}")?;
        }
        Ok(())
    }
}

impl Config {
    /// Validates the loaded configuration.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`] in the report. Call
    /// [`Config::validate_full`] if you want every problem at once.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let report = self.validate_full();
        if let Some(err) = report.errors.into_iter().next() {
            return Err(err);
        }
        Ok(())
    }

    /// Returns every issue \u2014 errors *and* warnings \u2014 found in the
    /// configuration.
    #[must_use]
    pub fn validate_full(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        validate_cors(self, &mut report);
        validate_limits(self, &mut report);
        validate_rate_limit(&self.rate_limit, &mut report);
        validate_upstream(self, &mut report);
        validate_tls(self, &mut report);
        validate_ssrf(self, &mut report);
        report
    }
}

fn validate_cors(cfg: &Config, report: &mut ValidationReport) {
    if matches!(cfg.cors.policy, CorsPolicyKind::Wildcard) && cfg.cors.allow_credentials {
        report.errors.push(ConfigError::new(
            "cors.allow_credentials",
            "wildcard policy + allow_credentials=true is rejected by browsers; \
             switch the policy to `reflect` or `explicit`",
        ));
    }

    if matches!(cfg.cors.policy, CorsPolicyKind::Explicit) && cfg.cors.explicit.is_empty() {
        report.errors.push(ConfigError::new(
            "cors.explicit",
            "policy is `explicit` but no origins are listed; the proxy would reject \
             every cross-origin request",
        ));
    }

    if cfg.cors.allow_private_network && !matches!(cfg.cors.policy, CorsPolicyKind::Explicit) {
        report.warnings.push(ConfigError::new(
            "cors.allow_private_network",
            "Private Network Access should usually be paired with `policy = \"explicit\"` \
             so that only known origins can reach the private network",
        ));
    }
}

fn validate_limits(cfg: &Config, report: &mut ValidationReport) {
    if cfg.limits.connect_timeout >= cfg.limits.request_timeout {
        report.warnings.push(ConfigError::new(
            "limits.connect_timeout",
            "connect_timeout >= request_timeout: the request budget will be exhausted \
             before the upstream can respond",
        ));
    }
    if cfg.limits.max_redirects > 32 {
        report.warnings.push(ConfigError::new(
            "limits.max_redirects",
            "values above 32 are rarely useful and amplify resource consumption",
        ));
    }
    if cfg.limits.max_request_body_bytes == 0 {
        report.errors.push(ConfigError::new(
            "limits.max_request_body_bytes",
            "must be > 0",
        ));
    }
}

fn validate_rate_limit(cfg: &RateLimitConfig, report: &mut ValidationReport) {
    if !cfg.enabled {
        return;
    }

    let any_enabled = cfg.origin.rps > 0
        || cfg.ip.rps > 0
        || cfg.target_host.rps > 0
        || cfg.global.rps > 0
        || cfg.global.inflight_max > 0;
    if !any_enabled {
        report.errors.push(ConfigError::new(
            "rate_limit",
            "rate_limit.enabled = true but every dimension is at 0; either \
             disable rate-limiting or set at least one of origin.rps / ip.rps / \
             target_host.rps / global.rps / global.inflight_max",
        ));
    }

    check_dimension(
        report,
        "rate_limit.origin",
        cfg.origin.rps,
        cfg.origin.burst,
    );
    check_dimension(report, "rate_limit.ip", cfg.ip.rps, cfg.ip.burst);
    check_dimension(
        report,
        "rate_limit.target_host",
        cfg.target_host.rps,
        cfg.target_host.burst,
    );
    check_dimension(
        report,
        "rate_limit.global",
        cfg.global.rps,
        cfg.global.burst,
    );
}

fn check_dimension(report: &mut ValidationReport, prefix: &'static str, rps: u32, burst: u32) {
    if rps == 0 {
        return; // disabled, nothing to check
    }
    if burst == 0 {
        report.errors.push(ConfigError::new(
            format!("{prefix}.burst"),
            "must be > 0 when the dimension's rps is > 0",
        ));
    } else if burst < rps {
        report.warnings.push(ConfigError::new(
            format!("{prefix}.burst"),
            "burst smaller than rps gives no headroom for bursty clients",
        ));
    }
}

fn validate_upstream(cfg: &Config, report: &mut ValidationReport) {
    if cfg.upstream.pool_max_idle_per_host == 0 {
        report.errors.push(ConfigError::new(
            "upstream.pool_max_idle_per_host",
            "must be > 0; setting to 0 disables connection reuse and \
             collapses throughput",
        ));
    }
    if cfg.upstream.user_agent.trim().is_empty() {
        report.errors.push(ConfigError::new(
            "upstream.user_agent",
            "must be a non-empty token",
        ));
    }
}

fn validate_tls(cfg: &Config, report: &mut ValidationReport) {
    let Some(tls) = cfg.server.tls.as_ref() else {
        return;
    };

    if !tls.cert_path.is_file() {
        report.errors.push(ConfigError::new(
            "server.tls.cert_path",
            format!("certificate file not found: {}", tls.cert_path.display()),
        ));
    }
    if !tls.key_path.is_file() {
        report.errors.push(ConfigError::new(
            "server.tls.key_path",
            format!("private key file not found: {}", tls.key_path.display()),
        ));
    }
}

fn validate_ssrf(cfg: &Config, report: &mut ValidationReport) {
    use crate::config::SsrfMode;

    if matches!(
        cfg.ssrf.mode,
        SsrfMode::Permissive {
            allow_private: true
        }
    ) && cfg.ssrf.extra_blocked_cidrs.is_empty()
    {
        report.warnings.push(ConfigError::new(
            "ssrf.mode",
            "permissive mode with `allow_private=true` and no extra block list \
             admits every IP, including AWS / GCP metadata. Add explicit \
             `extra_blocked_cidrs` or switch to `strict` for production.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CorsPolicyKind, ServerConfig};

    fn base() -> Config {
        Config::defaults()
    }

    #[test]
    fn defaults_validate_clean() {
        let report = base().validate_full();
        assert!(!report.has_errors(), "{report}");
    }

    #[test]
    fn wildcard_with_credentials_is_rejected() {
        let mut cfg = base();
        cfg.cors.policy = CorsPolicyKind::Wildcard;
        cfg.cors.allow_credentials = true;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.path, "cors.allow_credentials");
    }

    #[test]
    fn explicit_without_origins_is_rejected() {
        let mut cfg = base();
        cfg.cors.policy = CorsPolicyKind::Explicit;
        cfg.cors.explicit = Vec::new();
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.path, "cors.explicit");
    }

    #[test]
    fn rate_limit_enabled_with_all_dimensions_zero_is_rejected() {
        let mut cfg = base();
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.origin.rps = 0;
        cfg.rate_limit.ip.rps = 0;
        cfg.rate_limit.target_host.rps = 0;
        cfg.rate_limit.global.rps = 0;
        cfg.rate_limit.global.inflight_max = 0;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.path, "rate_limit");
    }

    #[test]
    fn rate_limit_dimension_with_zero_burst_is_rejected() {
        let mut cfg = base();
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.origin.rps = 10;
        cfg.rate_limit.origin.burst = 0;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.path, "rate_limit.origin.burst");
    }

    #[test]
    fn pool_max_idle_zero_is_rejected() {
        let mut cfg = base();
        cfg.upstream.pool_max_idle_per_host = 0;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.path, "upstream.pool_max_idle_per_host");
    }

    #[test]
    fn missing_tls_cert_is_rejected() {
        let mut cfg = base();
        cfg.server = ServerConfig {
            tls: Some(crate::config::TlsConfig {
                cert_path: std::path::PathBuf::from("/does/not/exist.pem"),
                key_path: std::path::PathBuf::from("/does/not/exist.key"),
                client_ca_path: None,
                alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            }),
            ..cfg.server
        };
        let report = cfg.validate_full();
        assert!(report.has_errors());
        let paths: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"server.tls.cert_path"));
        assert!(paths.contains(&"server.tls.key_path"));
    }
}
