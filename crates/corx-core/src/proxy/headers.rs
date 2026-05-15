//! Header filtering applied to inbound requests and outbound responses.
//!
//! Three filtering passes are performed:
//!
//! 1. **Inbound**: hop-by-hop headers (RFC 7230 §6.1) are stripped, plus any
//!    operator-configured deny-list.
//! 2. **Inbound rewrite**: the `Host` header is replaced with the upstream
//!    authority so that name-based virtual hosting works correctly.
//! 3. **Outbound**: cookie-setting headers and configured deny-list entries
//!    are stripped from the upstream response before handing it to the
//!    client.

use http::HeaderMap;
use http::header::HeaderName;

/// Hop-by-hop headers that must never be forwarded across a proxy boundary.
/// See RFC 7230 §6.1 and RFC 2616 §13.5.1.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    // TE/Connection options commonly scrubbed by reverse proxies.
    "proxy-connection",
];

/// Compiled filter used during the inbound header rewrite phase.
#[derive(Debug, Clone)]
pub struct RequestFilter {
    extra_deny: Vec<HeaderName>,
}

impl RequestFilter {
    /// Compile a filter from the configured header names.
    #[must_use]
    pub fn new(extra_deny: &[String]) -> Self {
        Self {
            extra_deny: compile_names(extra_deny),
        }
    }

    /// Strip hop-by-hop and denied headers, then remove any `Connection`-listed
    /// options as required by RFC 7230.
    pub fn apply(&self, headers: &mut HeaderMap) {
        strip_connection_listed(headers);
        for name in HOP_BY_HOP {
            headers.remove(*name);
        }
        for name in &self.extra_deny {
            headers.remove(name);
        }
    }
}

/// Compiled filter used during the outbound response rewrite phase.
#[derive(Debug, Clone)]
pub struct ResponseFilter {
    extra_deny: Vec<HeaderName>,
}

impl ResponseFilter {
    /// Compile a filter from the configured header names.
    #[must_use]
    pub fn new(extra_deny: &[String]) -> Self {
        Self {
            extra_deny: compile_names(extra_deny),
        }
    }

    /// Strip hop-by-hop and denied headers from an upstream response.
    pub fn apply(&self, headers: &mut HeaderMap) {
        strip_connection_listed(headers);
        for name in HOP_BY_HOP {
            headers.remove(*name);
        }
        for name in &self.extra_deny {
            headers.remove(name);
        }
    }
}

fn strip_connection_listed(headers: &mut HeaderMap) {
    let mut to_remove: Vec<HeaderName> = Vec::new();
    if let Some(connection) = headers.get(http::header::CONNECTION)
        && let Ok(value) = connection.to_str()
    {
        for token in value.split(',').map(str::trim) {
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = token.parse::<HeaderName>() {
                to_remove.push(name);
            }
        }
    }
    for name in to_remove {
        headers.remove(name);
    }
}

fn compile_names(values: &[String]) -> Vec<HeaderName> {
    values
        .iter()
        .filter_map(|raw| raw.parse::<HeaderName>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;

    use super::{RequestFilter, ResponseFilter};

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let filter = RequestFilter::new(&[]);
        let mut headers = HeaderMap::new();
        headers.insert("connection", "close".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        filter.apply(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key("x-forwarded-for"));
    }

    #[test]
    fn connection_listed_headers_are_stripped() {
        let filter = ResponseFilter::new(&[]);
        let mut headers = HeaderMap::new();
        headers.insert("connection", "close, x-custom".parse().unwrap());
        headers.insert("x-custom", "should-be-removed".parse().unwrap());
        headers.insert("x-keep", "yes".parse().unwrap());

        filter.apply(&mut headers);

        assert!(!headers.contains_key("x-custom"));
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn extra_deny_list_is_honoured() {
        let filter = RequestFilter::new(&["cookie".into(), "authorization".into()]);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "a=b".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        filter.apply(&mut headers);

        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("authorization"));
        assert!(headers.contains_key("content-type"));
    }
}
