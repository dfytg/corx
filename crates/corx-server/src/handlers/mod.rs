//! HTTP handlers: the proxy endpoint and the operational endpoints.
//!
//! Split across two siblings:
//!
//! * [`ops`] hosts the lightweight GET endpoints (`/livez`, `/readyz`,
//!   `/healthz`, `/iscorsneeded`, `/metrics`, landing page, fallback).
//! * [`proxy`] hosts the actual forwarding pipeline along with its
//!   request/response shaping helpers.

mod ops;
mod outbound;
mod proxy;

pub(crate) use self::ops::{
    healthz, is_cors_needed, livez, not_found, prometheus_metrics, readyz, usage,
};
pub(crate) use self::proxy::proxy;
