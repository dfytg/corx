//! Forwarding header injection.
//!
//! When `corx` sits in front of an upstream service the canonical
//! `X-Forwarded-*` and RFC 7239 `Forwarded` headers tell that service who
//! the original caller was, what scheme the inbound request used and which
//! `Host` the browser thought it was talking to. This module owns the
//! formatting rules so they stay in lock-step regardless of the surrounding
//! HTTP framework.
//!
//! Configuration knobs (see [`crate::config::ForwardedConfig`]):
//!
//! * `inject = true` (default) \u2014 stamp every outgoing request with the
//!   forwarded headers.
//! * `trust_inbound_xff = false` (default) \u2014 if the operator runs `corx`
//!   directly facing the public internet, leaving this off prevents callers
//!   from poisoning logs with a forged `X-Forwarded-For` chain.
//! * `inject_request_id = true` (default) \u2014 generate a UUID v7 when the
//!   client did not supply one. UUID v7 is time-ordered which keeps log
//!   index locality good.

use std::net::IpAddr;

use http::HeaderMap;
use http::header::{self, HeaderName, HeaderValue};

use crate::config::ForwardedConfig;
use crate::proxy::url_parser::TargetUrl;

/// Header carrying the canonical request identifier.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PORT: HeaderName = HeaderName::from_static("x-forwarded-port");

/// Inputs gathered from the inbound listener.
#[derive(Debug, Clone, Copy)]
pub struct InboundContext<'a> {
    /// IP address of the immediate TCP peer (after any reverse proxy).
    pub client_ip: Option<IpAddr>,
    /// Inbound request scheme (`http` or `https`).
    pub scheme: &'a str,
    /// `Host` header observed on the inbound request, if any.
    pub host: Option<&'a str>,
    /// TCP port that the inbound listener accepted the connection on.
    pub local_port: u16,
}

/// Stamp the forwarded headers and request id onto the outbound request
/// header map.
///
/// Existing values are preserved or appended to according to the configured
/// trust model. The function is idempotent: invoking it twice on the same
/// header map is harmless.
pub fn inject(
    headers: &mut HeaderMap,
    inbound: InboundContext<'_>,
    target: &TargetUrl,
    cfg: &ForwardedConfig,
) {
    if cfg.inject_request_id {
        ensure_request_id(headers);
    }

    if !cfg.inject {
        return;
    }

    if let Some(client) = inbound.client_ip {
        if cfg.trust_inbound_xff {
            append_xff(headers, client);
        } else {
            replace_xff(headers, client);
        }
    }

    set_static(headers, &X_FORWARDED_PROTO, inbound.scheme);
    if let Some(host) = inbound.host {
        set_static(headers, &X_FORWARDED_HOST, host);
    }
    if let Ok(value) = HeaderValue::from_str(&inbound.local_port.to_string()) {
        headers.insert(X_FORWARDED_PORT, value);
    }

    if let Some(value) = build_forwarded_value(inbound, target) {
        headers.insert(header::FORWARDED, value);
    }
}

fn ensure_request_id(headers: &mut HeaderMap) {
    if headers.contains_key(&REQUEST_ID_HEADER) {
        return;
    }
    let id = uuid::Uuid::now_v7().to_string();
    if let Ok(value) = HeaderValue::from_str(&id) {
        headers.insert(REQUEST_ID_HEADER, value);
    }
}

fn append_xff(headers: &mut HeaderMap, client: IpAddr) {
    let appended = match headers.get(&X_FORWARDED_FOR) {
        Some(existing) => match existing.to_str() {
            Ok(prev) => format!("{prev}, {client}"),
            Err(_) => client.to_string(),
        },
        None => client.to_string(),
    };
    if let Ok(value) = HeaderValue::from_str(&appended) {
        headers.insert(X_FORWARDED_FOR, value);
    }
}

fn replace_xff(headers: &mut HeaderMap, client: IpAddr) {
    if let Ok(value) = HeaderValue::from_str(&client.to_string()) {
        headers.insert(X_FORWARDED_FOR, value);
    }
}

fn set_static(headers: &mut HeaderMap, name: &HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name.clone(), value);
    }
}

fn build_forwarded_value(inbound: InboundContext<'_>, target: &TargetUrl) -> Option<HeaderValue> {
    let mut parts: Vec<String> = Vec::with_capacity(4);
    if let Some(ip) = inbound.client_ip {
        let token = match ip {
            IpAddr::V4(v4) => format!("for={v4}"),
            IpAddr::V6(v6) => format!("for=\"[{v6}]\""),
        };
        parts.push(token);
    }
    parts.push(format!("proto={}", inbound.scheme));
    if let Some(host) = inbound.host {
        parts.push(format!("host={host}"));
    }
    parts.push(format!("by={}", target.host));
    HeaderValue::from_str(&parts.join(";")).ok()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr as _;

    use http::HeaderMap;

    use super::{InboundContext, REQUEST_ID_HEADER, inject};
    use crate::config::ForwardedConfig;
    use crate::proxy::url_parser::extract_target;

    fn target() -> crate::proxy::url_parser::TargetUrl {
        let uri: http::Uri = "/https://api.example.com/v1".parse().unwrap();
        extract_target(&uri).unwrap()
    }

    fn cfg() -> ForwardedConfig {
        ForwardedConfig {
            inject: true,
            trust_inbound_xff: false,
            inject_request_id: true,
        }
    }

    #[test]
    fn injects_xff_proto_host_port() {
        let mut headers = HeaderMap::new();
        let inbound = InboundContext {
            client_ip: Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            scheme: "https",
            host: Some("proxy.example"),
            local_port: 8080,
        };
        inject(&mut headers, inbound, &target(), &cfg());
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "203.0.113.5");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "proxy.example");
        assert_eq!(headers.get("x-forwarded-port").unwrap(), "8080");
        let forwarded = headers.get("forwarded").unwrap().to_str().unwrap();
        assert!(forwarded.contains("for=203.0.113.5"));
        assert!(forwarded.contains("proto=https"));
        assert!(forwarded.contains("host=proxy.example"));
    }

    #[test]
    fn replaces_inbound_xff_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let inbound = InboundContext {
            client_ip: Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            scheme: "http",
            host: None,
            local_port: 80,
        };
        inject(&mut headers, inbound, &target(), &cfg());
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "203.0.113.5");
    }

    #[test]
    fn appends_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let inbound = InboundContext {
            client_ip: Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            scheme: "http",
            host: None,
            local_port: 80,
        };
        let mut cfg = cfg();
        cfg.trust_inbound_xff = true;
        inject(&mut headers, inbound, &target(), &cfg);
        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "1.2.3.4, 203.0.113.5"
        );
    }

    #[test]
    fn generates_request_id_when_missing() {
        let mut headers = HeaderMap::new();
        let inbound = InboundContext {
            client_ip: None,
            scheme: "https",
            host: None,
            local_port: 443,
        };
        inject(&mut headers, inbound, &target(), &cfg());
        let id = headers.get(REQUEST_ID_HEADER).unwrap().to_str().unwrap();
        // UUID v7 is 36 characters long, dash-separated.
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::from_str(id).is_ok());
    }

    #[test]
    fn preserves_inbound_request_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "client-supplied".parse().unwrap());
        let inbound = InboundContext {
            client_ip: None,
            scheme: "https",
            host: None,
            local_port: 443,
        };
        inject(&mut headers, inbound, &target(), &cfg());
        assert_eq!(headers.get("x-request-id").unwrap(), "client-supplied");
    }
}
