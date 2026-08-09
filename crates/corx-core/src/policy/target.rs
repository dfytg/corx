//! Target host / scheme admission.

use http::Uri;

use crate::config::{TargetConfig, TargetMode};
use crate::error::ProxyError;
use crate::proxy::url_parser::TargetUrl;

/// Compiled target admission policy.
///
/// Applied on the **initial** proxy target and on **every** redirect hop so
/// allowlists / denylists / `https_only` cannot be bypassed via 3xx.
#[derive(Debug, Clone)]
pub struct TargetPolicy {
    mode: TargetMode,
    /// Lowercased host patterns; entries starting with `.` are suffix matches.
    hosts: Vec<String>,
    schemes: Vec<String>,
    https_only: bool,
}

impl TargetPolicy {
    /// Compile from configuration.
    #[must_use]
    pub fn from_config(cfg: &TargetConfig) -> Self {
        Self {
            mode: cfg.mode,
            hosts: cfg
                .hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            schemes: if cfg.schemes.is_empty() {
                vec!["https".into(), "http".into()]
            } else {
                cfg.schemes
                    .iter()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .collect()
            },
            https_only: cfg.https_only,
        }
    }

    /// Admit or reject a parsed target URL.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::TargetNotAllowed`] when the host or scheme is
    /// outside policy.
    pub fn check(&self, target: &TargetUrl) -> Result<(), ProxyError> {
        self.check_authority(target.url.scheme(), &target.host)
    }

    /// Admit or reject a hop identified by scheme and host (redirects).
    ///
    /// Host comparison is case-insensitive. The host must already be in
    /// ASCII / punycode form when it comes from the URL parser; redirect
    /// `Location` hosts are lowercased here for matching.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::TargetNotAllowed`] when the host or scheme is
    /// outside policy.
    pub fn check_authority(&self, scheme: &str, host: &str) -> Result<(), ProxyError> {
        let scheme = scheme.to_ascii_lowercase();
        if self.https_only && scheme != "https" {
            return Err(ProxyError::TargetNotAllowed(format!(
                "scheme `{scheme}` rejected (https_only)"
            )));
        }
        if !self.schemes.iter().any(|s| s == &scheme) {
            return Err(ProxyError::TargetNotAllowed(format!(
                "scheme `{scheme}` is not allowed"
            )));
        }

        let host = host.to_ascii_lowercase();
        let matched = self
            .hosts
            .iter()
            .any(|pattern| host_matches(pattern, &host));

        match self.mode {
            TargetMode::AnyPublic => Ok(()),
            TargetMode::Allowlist => {
                if self.hosts.is_empty() {
                    return Err(ProxyError::TargetNotAllowed(
                        "allowlist is empty".to_owned(),
                    ));
                }
                if matched {
                    Ok(())
                } else {
                    Err(ProxyError::TargetNotAllowed(format!(
                        "host `{host}` is not on the allowlist"
                    )))
                }
            }
            TargetMode::Denylist => {
                if matched {
                    Err(ProxyError::TargetNotAllowed(format!(
                        "host `{host}` is denylisted"
                    )))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Admit or reject a hop [`Uri`] (used on every redirect continue).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::TargetNotAllowed`] or [`ProxyError::InvalidUrl`]
    /// when the URI lacks a usable scheme/host or fails policy.
    pub fn check_uri(&self, uri: &Uri) -> Result<(), ProxyError> {
        let scheme = uri.scheme_str().ok_or_else(|| {
            ProxyError::InvalidUrl("hop URI lacks a scheme".to_owned())
        })?;
        let host = uri.host().ok_or_else(|| {
            ProxyError::InvalidUrl("hop URI lacks a host".to_owned())
        })?;
        self.check_authority(scheme, host)
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    pattern.strip_prefix('.').map_or_else(
        || host == pattern,
        |suffix| host == suffix || host.ends_with(pattern),
    )
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use super::*;
    use crate::config::{TargetConfig, TargetMode};
    use crate::proxy::url_parser::extract_target;

    fn target(url: &str) -> TargetUrl {
        let path = format!("/{url}");
        let uri: Uri = path.parse().unwrap();
        extract_target(&uri).unwrap()
    }

    #[test]
    fn any_public_admits_http_and_https() {
        let pol = TargetPolicy::from_config(&TargetConfig::default());
        assert!(pol.check(&target("https://example.com/a")).is_ok());
        assert!(pol.check(&target("http://example.com/a")).is_ok());
    }

    #[test]
    fn https_only_rejects_http() {
        let cfg = TargetConfig {
            https_only: true,
            ..TargetConfig::default()
        };
        let pol = TargetPolicy::from_config(&cfg);
        assert!(pol.check(&target("http://example.com/a")).is_err());
        assert!(pol.check(&target("https://example.com/a")).is_ok());
    }

    #[test]
    fn allowlist_suffix_match() {
        let pol = TargetPolicy::from_config(&TargetConfig {
            mode: TargetMode::Allowlist,
            hosts: vec![".example.com".into()],
            ..TargetConfig::default()
        });
        assert!(pol.check(&target("https://a.example.com/x")).is_ok());
        assert!(pol.check(&target("https://example.com/x")).is_ok());
        assert!(pol.check(&target("https://evil.com/x")).is_err());
    }

    #[test]
    fn denylist_blocks_pattern() {
        let pol = TargetPolicy::from_config(&TargetConfig {
            mode: TargetMode::Denylist,
            hosts: vec!["bad.test".into()],
            ..TargetConfig::default()
        });
        assert!(pol.check(&target("https://bad.test/x")).is_err());
        assert!(pol.check(&target("https://good.test/x")).is_ok());
    }

    #[test]
    fn check_uri_enforces_allowlist_on_redirect_hop() {
        let pol = TargetPolicy::from_config(&TargetConfig {
            mode: TargetMode::Allowlist,
            hosts: vec!["allowed.test".into()],
            ..TargetConfig::default()
        });
        let ok: Uri = "https://allowed.test/next".parse().unwrap();
        let bad: Uri = "https://evil.test/next".parse().unwrap();
        assert!(pol.check_uri(&ok).is_ok());
        assert!(pol.check_uri(&bad).is_err());
    }
}
