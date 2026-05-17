//! Outbound request/response shaping helpers shared by the proxy handler.
//!
//! Kept in their own module so the [`super::proxy`] file stays focused on
//! the request lifecycle rather than the bookkeeping required to translate
//! between [`axum`] bodies and the upstream client body, or to stamp the
//! `Via` / `Host` / default `User-Agent` headers.

use axum::body::Body as AxumBody;
use corx_core::error::ProxyError;
use corx_core::proxy::{TargetUrl, UpstreamBody};
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue, header};
use http_body_util::BodyExt as _;

use crate::observability::CountingBody;

/// Header that advertises the resolved upstream URL to the caller.
pub(super) const EXPOSE_URL_HEADER: HeaderName = HeaderName::from_static("x-corx-target-url");
/// Value appended to the `Via` header to mark our hop in the chain.
pub(super) const VIA_HEADER_VALUE: &str = "1.1 corx";

/// Insert the configured fallback `User-Agent` when the client did not
/// supply one. A present-but-malformed value is left untouched.
pub(super) fn inject_default_user_agent(headers: &mut HeaderMap, default_ua: &str) {
    if headers.contains_key(header::USER_AGENT) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(default_ua) {
        headers.insert(header::USER_AGENT, value);
    }
}

/// Rewrite the `Host` header so the upstream sees its own authority. The
/// previous value (typically the proxy's listener host) is discarded — it
/// was meaningful only for the inbound hop.
pub(super) fn set_host_from_target(headers: &mut HeaderMap, target: &TargetUrl) {
    let authority = target.url.port().map_or_else(
        || target.host.clone(),
        |port| format!("{}:{port}", target.host),
    );
    if let Ok(value) = HeaderValue::from_str(&authority) {
        headers.insert(header::HOST, value);
    }
}

/// Append our `Via` token to whatever the upstream sent (or start a fresh
/// header when none existed). Non-UTF8 inbound values are replaced rather
/// than concatenated — they cannot be safely round-tripped.
pub(super) fn append_via_header(headers: &mut HeaderMap) {
    let header_name = header::VIA;
    let new_value = headers.get(&header_name).map_or_else(
        || VIA_HEADER_VALUE.to_owned(),
        |existing| {
            existing.to_str().map_or_else(
                |_| VIA_HEADER_VALUE.to_owned(),
                |s| format!("{s}, {VIA_HEADER_VALUE}"),
            )
        },
    );
    if let Ok(value) = HeaderValue::from_str(&new_value) {
        headers.insert(header_name, value);
    }
}

/// Wrap an [`axum::body::Body`] in a [`CountingBody`] and erase the error
/// type via [`ProxyError::Internal`] so it can flow through the hyper
/// client.
pub(super) fn axum_to_upstream_body(body: AxumBody) -> UpstreamBody {
    let counted = CountingBody::new(body, "request");
    counted
        .map_err(|err| ProxyError::Internal(anyhow::Error::new(err)))
        .boxed_unsync()
}
