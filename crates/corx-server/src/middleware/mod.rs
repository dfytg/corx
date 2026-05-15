//! Request-level guards executed in front of the proxy handler.
//!
//! All middleware is implemented as `axum` extractors or `tower_http` layers
//! so that they compose cleanly. They are intentionally small and leaf-free:
//! the proxy handler owns all business logic.

pub mod origin_guard;
pub mod rate_limit;
pub mod request_guard;

pub use self::origin_guard::OriginPolicy;
pub use self::rate_limit::RateLimiter;
pub use self::request_guard::RequestGuard;
