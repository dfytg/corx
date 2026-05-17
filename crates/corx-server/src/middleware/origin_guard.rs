//! Origin blacklist / whitelist enforcement.

use std::collections::HashSet;

use corx_core::config::SecurityConfig;
use corx_core::error::ProxyError;
use corx_core::util::OriginSet;
use foldhash::fast::RandomState;
use http::header::ORIGIN;
use http::{HeaderMap, Method};

/// Compiled origin policy.
#[derive(Debug, Clone)]
pub struct OriginPolicy {
    blacklist: OriginSet,
    whitelist: OriginSet,
    blocked_methods: HashSet<Method, RandomState>,
    required_header_any_of: Vec<String>,
}

impl OriginPolicy {
    /// Compiles the security configuration into a fast-dispatch policy.
    #[must_use]
    pub fn from_config(cfg: &SecurityConfig) -> Self {
        let mut blocked_methods: HashSet<Method, RandomState> =
            HashSet::with_hasher(RandomState::default());
        for raw in &cfg.block_methods {
            if let Ok(method) = Method::from_bytes(raw.to_ascii_uppercase().as_bytes()) {
                blocked_methods.insert(method);
            }
        }

        Self {
            blacklist: to_origin_set(&cfg.origin_blacklist),
            whitelist: to_origin_set(&cfg.origin_whitelist),
            blocked_methods,
            required_header_any_of: cfg
                .require_header
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Validates an inbound request; returns `Ok(())` when the request is
    /// permitted to continue through the pipeline.
    ///
    /// # Errors
    ///
    /// Returns one of [`ProxyError::OriginNotAllowed`] or
    /// [`ProxyError::MissingHeader`] depending on which guard triggered.
    pub fn evaluate(&self, method: &Method, headers: &HeaderMap) -> Result<(), ProxyError> {
        if self.blocked_methods.contains(method) {
            return Err(ProxyError::OriginNotAllowed(format!(
                "method `{method}` is blocked"
            )));
        }

        let origin = headers.get(ORIGIN).and_then(|value| value.to_str().ok());
        match origin {
            Some(origin) => {
                if self.blacklist.contains(origin) {
                    return Err(ProxyError::OriginNotAllowed(origin.to_owned()));
                }
                if !self.whitelist.is_empty() && !self.whitelist.contains(origin) {
                    return Err(ProxyError::OriginNotAllowed(origin.to_owned()));
                }
            }
            None if !self.whitelist.is_empty() => {
                return Err(ProxyError::OriginNotAllowed("<missing origin>".into()));
            }
            None => {}
        }

        if !self.required_header_any_of.is_empty()
            && !self
                .required_header_any_of
                .iter()
                .any(|name| headers.contains_key(name.as_str()))
        {
            return Err(ProxyError::MissingHeader("required inbound header"));
        }

        Ok(())
    }
}

fn to_origin_set(values: &[String]) -> OriginSet {
    values.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use corx_core::config::SecurityConfig;
    use http::{HeaderMap, HeaderValue, Method};

    use super::OriginPolicy;

    fn make(cfg: &SecurityConfig) -> OriginPolicy {
        OriginPolicy::from_config(cfg)
    }

    fn headers(origin: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(origin) = origin {
            map.insert("origin", HeaderValue::from_str(origin).unwrap());
        }
        map
    }

    #[test]
    fn blacklist_blocks_origin() {
        let policy = make(&SecurityConfig {
            require_header: vec![],
            block_methods: vec![],
            remove_request_headers: vec![],
            remove_response_headers: vec![],
            origin_blacklist: vec!["https://bad.test".into()],
            origin_whitelist: vec![],
        });
        assert!(
            policy
                .evaluate(&Method::GET, &headers(Some("https://bad.test")))
                .is_err()
        );
    }

    #[test]
    fn whitelist_gates_origin() {
        let policy = make(&SecurityConfig {
            require_header: vec![],
            block_methods: vec![],
            remove_request_headers: vec![],
            remove_response_headers: vec![],
            origin_blacklist: vec![],
            origin_whitelist: vec!["https://ok.test".into()],
        });
        assert!(
            policy
                .evaluate(&Method::GET, &headers(Some("https://ok.test")))
                .is_ok()
        );
        assert!(
            policy
                .evaluate(&Method::GET, &headers(Some("https://no.test")))
                .is_err()
        );
        assert!(policy.evaluate(&Method::GET, &headers(None)).is_err());
    }

    #[test]
    fn blocked_method_is_rejected() {
        let policy = make(&SecurityConfig {
            require_header: vec![],
            block_methods: vec!["CONNECT".into()],
            remove_request_headers: vec![],
            remove_response_headers: vec![],
            origin_blacklist: vec![],
            origin_whitelist: vec![],
        });
        assert!(policy.evaluate(&Method::CONNECT, &headers(None)).is_err());
    }

    #[test]
    fn required_header_must_be_present() {
        let policy = make(&SecurityConfig {
            require_header: vec!["origin".into(), "x-requested-with".into()],
            block_methods: vec![],
            remove_request_headers: vec![],
            remove_response_headers: vec![],
            origin_blacklist: vec![],
            origin_whitelist: vec![],
        });
        assert!(policy.evaluate(&Method::GET, &headers(None)).is_err());
        assert!(
            policy
                .evaluate(&Method::GET, &headers(Some("https://ok.test")))
                .is_ok()
        );
    }
}
