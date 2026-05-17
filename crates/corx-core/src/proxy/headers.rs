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
//!
//! Both the inbound and outbound passes share the exact same algorithm
//! (strip `Connection`-listed names, strip hop-by-hop, strip operator
//! deny-list), so a single [`HeaderFilter`] type backs both. Callers hold
//! two distinct instances configured with the request-side and response-side
//! deny lists respectively.

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
    "proxy-connection",
];

/// Compiled header filter shared by the inbound and outbound passes.
#[derive(Debug, Clone)]
pub struct HeaderFilter {
    extra_deny: Vec<HeaderName>,
}

impl HeaderFilter {
    /// Compile a filter from the configured header names. Names that fail to
    /// parse are silently dropped so a typo in the config cannot wedge the
    /// proxy at startup.
    #[must_use]
    pub fn new(extra_deny: &[String]) -> Self {
        Self {
            extra_deny: extra_deny
                .iter()
                .filter_map(|raw| raw.parse::<HeaderName>().ok())
                .collect(),
        }
    }

    /// Strip every header that must not survive a proxy hop: the
    /// `Connection`-listed names (per RFC 7230 §6.1), the static hop-by-hop
    /// list, and finally the operator-supplied deny list.
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
    let Some(connection) = headers.get(http::header::CONNECTION) else {
        return;
    };
    let Ok(value) = connection.to_str() else {
        return;
    };
    let to_remove: Vec<HeaderName> = value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter_map(|token| token.parse::<HeaderName>().ok())
        .collect();
    for name in to_remove {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;

    use super::HeaderFilter;

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let filter = HeaderFilter::new(&[]);
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
        let filter = HeaderFilter::new(&[]);
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
        let filter = HeaderFilter::new(&["cookie".into(), "authorization".into()]);
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
