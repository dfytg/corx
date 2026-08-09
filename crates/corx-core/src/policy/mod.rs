//! Pure policy engines (no HTTP framework dependency).
//!
//! These types are compiled from configuration once and shared across
//! requests. They perform admission decisions only — no I/O.

mod circuit;
mod target;

pub use self::circuit::{CircuitBreaker, CircuitHop};
pub use self::target::TargetPolicy;
