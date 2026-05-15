//! Request-level guards executed in front of the proxy handler.
//!
//! All middleware is implemented as `axum` extractors or `tower_http` layers
//! so that they compose cleanly. They are intentionally small and leaf-free:
//! the proxy handler owns all business logic.

pub mod access_log;
pub mod cors;
pub mod load_shed;
pub mod origin_guard;
pub mod rate_limit;
pub mod request_guard;

pub use self::access_log::access_log_layer;
pub use self::cors::cors_layer;
pub use self::load_shed::load_shed_layer;
pub use self::origin_guard::OriginPolicy;
pub use self::rate_limit::RateLimiter;
pub use self::request_guard::RequestGuard;
