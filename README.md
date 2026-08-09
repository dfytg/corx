# CORX

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[crates-badge]: https://img.shields.io/crates/v/corx.svg
[crates-url]: https://crates.io/crates/corx
[docs-badge]: https://img.shields.io/docsrs/corx.svg
[docs-url]: https://docs.rs/corx
[ci-badge]: https://github.com/qntx/corx/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/qntx/corx/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**High-performance CORS forwarding proxy written in Rust — one binary streams any HTTP(S) target, synthesises browser CORS headers, SSRF-safe by construction.**

`corx` sits between browsers and upstream APIs that omit CORS. Path-prefix URL semantics match the classic [cors-anywhere](https://github.com/Rob--W/cors-anywhere) pattern (`/https://api.example.com/...`), while the hot path is zero-copy streaming on hyper 1.x + axum 0.8 + tokio: bodies are forwarded chunk-by-chunk, connections are pooled, outbound TLS and DNS are pure Rust, and every resolved address is vetted by an SSRF guard *before* the TCP connect.

## Quick Start

### Install the CLI

**Shell** (macOS / Linux):

```bash
curl -fsSL https://sh.qntx.fun/corx | sh
```

**PowerShell** (Windows):

```powershell
irm https://sh.qntx.fun/corx/ps | iex
```

Or via Cargo:

```bash
cargo install corx-cli
```

Optional features: `--features tls`, `mtls`, `otel`, or `full`.

### CLI Usage

```bash
# Serve (default config discovery + env overrides)
corx serve --config corx.example.toml

# Validate config
corx check --config corx.example.toml

# Dump resolved config
corx dump --format toml
corx dump --format json

# Build identity
corx version
```

Proxy a request (path-prefix target URL):

```bash
curl -H 'Origin: http://localhost' \
     'http://localhost:8080/https://api.github.com/repos/qntx/corx'
```

From a git checkout without installing:

```bash
cargo run --release -p corx-cli -- serve --config corx.example.toml
```

Config sources, increasing precedence:

1. Built-in defaults  
2. `$CORX_CONFIG`, or `./corx.toml`, or `/etc/corx/config.toml`  
3. Environment variables `CORX_*` (nested keys use `__`, e.g. `CORX_SERVER__BIND=0.0.0.0:9000`)  
4. CLI `--config`

Full knob reference: [`corx.example.toml`](corx.example.toml) · [docs/](docs/).

### Container

```bash
docker build -t corx:dev .
docker run --rm -p 8080:8080 corx:dev

# Full local stack (corx + Prometheus + Grafana + OTLP collector)
docker compose up -d
```

Multi-arch GHCR images are published **on version tags** only (`v*`).

### Library Usage

```toml
# Default is the HTTP stack only — enable TLS / OTEL explicitly when needed.
corx = { version = "0.2", features = ["tls", "otel"] }
# Optional: `full` (= tls + mtls + otel); or depend on corx-core / corx-server alone
```

```rust
use corx::{AppState, Config, ServerBuild, build_router, run};
use corx::server::config_loader;
use corx::server::observability::{init_metrics, init_tracing};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config_loader::load(None)?;
    init_tracing(&config.observability)?;
    let metrics = init_metrics()?;
    let build = ServerBuild::from_config(config.clone(), metrics)?;
    let ready = std::sync::Arc::clone(&build.ready);
    let router = build_router(AppState::new(build));
    run(&config.server, router, ready).await
}
```

Feature flags on `corx` / `corx-cli`: `tls`, `mtls`, `fips`, `otel`, `full`.

## Design

- **End-to-end streaming** — request/response bodies forwarded chunk-by-chunk; nothing buffered on the hot path
- **SSRF-safe DNS** — every resolve result checked against reserved/private CIDRs inside a custom hyper resolver; re-validated on each redirect hop
- **CORS policies** — `wildcard` / `reflect` / `explicit` (`origins` + `allow_any_origin`); preflights short-circuit; CORS stamped on errors
- **Guards by default** — preflight joins origin (and optional rate) guards; multi-dimensional GCRA; per-host circuit breaker; optional bearer / mTLS
- **cors-anywhere semantics** — path-prefix absolute URLs, cookie stripping by default, Origin allow/deny lists
- **Fail-closed defaults** — strict SSRF, fail-closed CORS reflection, CONNECT/TRACE blocked
- **Enterprise self-host** — single static binary, Helm chart, distroless image, cargo-deny
- **Layered crates** — `corx-cli` → `corx` → (`corx-server` → `corx-core`)
- **Strict workspace lints** — Clippy pedantic/nursery/correctness, `forbid(unsafe_code)`, `rust_2018_idioms` deny

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
