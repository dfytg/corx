//! Extracts and validates the upstream target URL from the inbound request.
//!
//! Two address formats are accepted, matching industry conventions:
//!
//! * **Path form** — `GET /<target-url>` (cors-anywhere style). The scheme is
//!   optional; it defaults to `http://`, or `https://` when port `443` is
//!   specified.
//! * **Query form** — `GET /?url=<target-url>` (percent-encoded).
//!
//! All strings are percent-decoded, and IDN hostnames are transcoded to
//! punycode so that the upstream DNS resolver can handle them.

use http::Uri;
use http::uri::PathAndQuery;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::error::ProxyError;

/// A validated target URL.
#[derive(Debug, Clone)]
pub struct TargetUrl {
    /// Fully-qualified, percent-encoded URL, ready to be sent upstream.
    pub url: Url,
    /// Punycode-encoded hostname (never empty).
    pub host: String,
    /// Effective port (either explicit or default for the scheme).
    pub port: u16,
}

impl TargetUrl {
    /// Rebuilds a `http::Uri` suitable for constructing the outbound request.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored URL cannot be projected onto a valid
    /// `http::Uri` (e.g. its path/query exceed the parser's limits).
    pub fn to_uri(&self) -> Result<Uri, ProxyError> {
        let path = self.url.path();
        let query = self.url.query();
        let path_and_query = match query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_owned(),
        };

        let pq = PathAndQuery::try_from(path_and_query)
            .map_err(|err| ProxyError::InvalidUrl(format!("invalid path/query: {err}")))?;

        let authority = match self.url.port() {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        };

        Uri::builder()
            .scheme(self.url.scheme())
            .authority(authority)
            .path_and_query(pq)
            .build()
            .map_err(|err| ProxyError::InvalidUrl(format!("uri build failed: {err}")))
    }
}

/// Extracts the target URL from either the request path or the `url` query parameter.
///
/// # Errors
///
/// Returns [`ProxyError::InvalidUrl`] if the request does not encode a
/// well-formed HTTP(S) URL, has an unsupported scheme, or lacks a hostname.
pub fn extract_target(uri: &Uri) -> Result<TargetUrl, ProxyError> {
    let candidate = candidate_from_uri(uri)?;
    let decoded = percent_decode_str(&candidate)
        .decode_utf8()
        .map_err(|_| ProxyError::InvalidUrl("target contains invalid utf-8".to_owned()))?
        .into_owned();

    let normalized = normalize_scheme(&decoded)?;
    let parsed = Url::parse(&normalized)
        .map_err(|err| ProxyError::InvalidUrl(format!("url parse failed: {err}")))?;

    validate(parsed)
}

fn candidate_from_uri(uri: &Uri) -> Result<String, ProxyError> {
    if let Some(query) = uri.query()
        && let Some(url_value) = find_query_value(query, "url")
    {
        return Ok(url_value.to_owned());
    }

    let path = uri.path();
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidUrl("no target url supplied".to_owned()));
    }
    if let Some(query) = uri.query() {
        Ok(format!("{trimmed}?{query}"))
    } else {
        Ok(trimmed.to_owned())
    }
}

fn find_query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

fn normalize_scheme(raw: &str) -> Result<String, ProxyError> {
    // If a scheme is already present, accept only http / https.
    if let Some((scheme_part, _)) = raw.split_once("://") {
        let scheme = scheme_part.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(ProxyError::InvalidUrl(format!(
                "unsupported scheme `{scheme}`"
            )));
        }
        return Ok(raw.to_owned());
    }

    // No scheme: replicate cors-anywhere behaviour — port 443 implies https.
    let host_part = raw.split('/').next().unwrap_or(raw);
    let scheme = match host_part.rsplit_once(':') {
        Some((_, port)) if port == "443" => "https",
        _ => "http",
    };
    Ok(format!("{scheme}://{raw}"))
}

fn validate(mut parsed: Url) -> Result<TargetUrl, ProxyError> {
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(ProxyError::InvalidUrl(format!(
                "unsupported scheme `{other}`"
            )));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::InvalidUrl("missing hostname".to_owned()))?;
    if host.is_empty() {
        return Err(ProxyError::InvalidUrl("empty hostname".to_owned()));
    }

    // Transcode IDN hostnames to punycode for consistent upstream handling.
    let ascii_host = idna::domain_to_ascii_cow(host.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|err| ProxyError::InvalidUrl(format!("invalid IDN host: {err}")))?
        .into_owned();
    if ascii_host != host {
        parsed
            .set_host(Some(&ascii_host))
            .map_err(|err| ProxyError::InvalidUrl(format!("cannot set host: {err}")))?;
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ProxyError::InvalidUrl("unable to determine port for scheme".to_owned()))?;

    Ok(TargetUrl {
        url: parsed,
        host: ascii_host,
        port,
    })
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use super::extract_target;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn path_form_with_scheme() {
        let target = extract_target(&uri("/https://api.example.com/v1/data")).unwrap();
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn path_form_without_scheme_defaults_to_http() {
        let target = extract_target(&uri("/api.example.com/v1/data")).unwrap();
        assert_eq!(target.url.scheme(), "http");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn path_form_port_443_implies_https() {
        let target = extract_target(&uri("/api.example.com:443/v1")).unwrap();
        assert_eq!(target.url.scheme(), "https");
    }

    #[test]
    fn query_form_is_accepted() {
        let encoded = "/?url=https%3A%2F%2Fapi.example.com%2Fpath";
        let target = extract_target(&uri(encoded)).unwrap();
        assert_eq!(target.host, "api.example.com");
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(extract_target(&uri("/")).is_err());
    }

    #[test]
    fn ftp_is_rejected() {
        assert!(extract_target(&uri("/ftp://example.com/")).is_err());
    }

    #[test]
    fn idn_host_is_punycoded() {
        let target = extract_target(&uri("/https://münchen.de/")).unwrap();
        assert_eq!(target.host, "xn--mnchen-3ya.de");
    }
}
