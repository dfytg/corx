//! Core forwarding pipeline: URL parsing, CORS shaping, SSRF protection and
//! upstream execution. This module is framework-agnostic (no `axum`
//! dependency) so that it can be embedded in alternative HTTP stacks.

pub mod cors;
pub mod forwarded;
pub mod headers;
pub mod redirect;
pub mod ssrf;
pub mod upstream;
pub mod url_parser;

pub use self::cors::{
    CorsPolicy, apply_to_error_response, apply_to_response, build_preflight_response, is_preflight,
};
pub use self::forwarded::{InboundContext, REQUEST_ID_HEADER, inject as inject_forwarded};
pub use self::headers::{RequestFilter, ResponseFilter};
pub use self::ssrf::{SsrfGuard, build_resolver};
pub use self::upstream::{Upstream, UpstreamBody, UpstreamConfig};
pub use self::url_parser::{TargetUrl, extract_target};
