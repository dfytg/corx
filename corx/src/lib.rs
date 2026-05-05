//! `corx` — a high-performance CORS forwarding proxy.
//!
//! The crate is organised as a library that exposes the proxy engine,
//! middleware stack, configuration loader and server lifecycle. The
//! accompanying binary (`src/main.rs`) is a thin entry point that wires the
//! pieces together.
//!
//! All public types are re-exported from the top-level modules below; the
//! hot path is framework-agnostic (lives under [`proxy`]), while [`server`]
//! and [`middleware`] are axum/tower specific and can be swapped out if
//! another HTTP stack is ever desired.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cli;
pub mod config;
pub mod error;
pub mod middleware;
pub mod observability;
pub mod proxy;
pub mod server;
