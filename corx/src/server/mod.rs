//! `axum`-based HTTP server assembly and lifecycle management.

mod handlers;
mod router;
mod shutdown;
mod state;

pub use self::router::{AppState, build_router};
pub use self::shutdown::run;
pub use self::state::ServerBuild;
