//! Shared utility types used by both the engine and the HTTP layer.
//!
//! The contents are deliberately tiny: only types that more than one module
//! needs end up here. Anything single-use stays in its caller's module.

use std::collections::HashSet;

use foldhash::fast::RandomState;

/// A `HashSet` of origin strings backed by foldhash's fast hasher.
///
/// Origins are compared case-sensitively (per RFC 6454 §4) so we do not bother
/// with case-folding on the key.
pub type OriginSet = HashSet<String, RandomState>;
