//! Layered configuration loader.
//!
//! The effective configuration is assembled from three sources, in order of
//! increasing precedence:
//!
//! 1. Built-in defaults (see [`Config::default`]).
//! 2. A TOML file discovered at `$CORX_CONFIG`, `./corx.toml` or
//!    `/etc/corx/config.toml`.
//! 3. Environment variables prefixed with `CORX_` (double underscore separates
//!    nested keys, e.g. `CORX_SERVER__BIND=0.0.0.0:9000`).
//!
//! CLI flags merged in by the binary take the highest precedence on top of
//! whatever this loader returns.

use std::path::{Path, PathBuf};

use corx_core::config::Config;
use figment::Figment;
use figment::providers::{Env, Format as _, Serialized, Toml};

/// Loads the layered configuration *and* runs the semantic validator.
///
/// `override_path`, when provided, supersedes the default discovery logic.
///
/// # Errors
///
/// Returns an error when the configuration file is present but invalid or
/// cannot be read, when an environment override cannot be parsed, or when
/// any [`corx_core::config::ConfigError`] surfaces during validation. Any
/// validation warnings are emitted via `tracing::warn!` so operators see
/// them without aborting startup.
pub fn load(override_path: Option<&Path>) -> anyhow::Result<Config> {
    let config = load_raw(override_path)?;
    let report = config.validate_full();
    for warn in &report.warnings {
        tracing::warn!(path = %warn.path, reason = %warn.reason, "config warning");
    }
    if let Some(err) = report.errors.into_iter().next() {
        return Err(err.into());
    }
    Ok(config)
}

/// Loads the configuration **without** running the validator. Useful for
/// `corx dump-config`, where the operator wants to see the merged result
/// even if it would fail validation.
///
/// # Errors
///
/// Same I/O / parsing errors as [`load`].
pub fn load_raw(override_path: Option<&Path>) -> anyhow::Result<Config> {
    let mut figment = Figment::from(Serialized::defaults(Config::default()));

    if let Some(path) = override_path {
        figment = figment.merge(Toml::file(path));
    } else if let Some(path) = discover_config_path() {
        figment = figment.merge(Toml::file(path));
    }

    figment = figment.merge(Env::prefixed("CORX_").split("__"));

    figment.extract().map_err(anyhow::Error::new)
}

fn discover_config_path() -> Option<PathBuf> {
    if let Ok(from_env) = std::env::var("CORX_CONFIG")
        && !from_env.is_empty()
    {
        return Some(PathBuf::from(from_env));
    }

    let candidates = ["corx.toml", "/etc/corx/config.toml"];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}
