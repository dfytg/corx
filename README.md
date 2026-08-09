# corx

High-performance CORS forwarding proxy written in Rust.

Stream any HTTP(S) target through a single binary while synthesising the CORS
headers that browsers require. Built on hyper 1.x + axum 0.8 + tokio, with
zero-copy streaming between client and upstream, pooled keep-alive
connections, pure-Rust TLS and DNS, and built-in SSRF protection.

## Highlights

- **End-to-end streaming** — request and response bodies are forwarded
  chunk-by-chunk; nothing is buffered in the proxy hot path.
- **SSRF-safe by construction** — every DNS result is checked against a
  curated list of reserved/private CIDRs before the TCP connection is
  attempted, inside a custom hyper resolver (not in user space).
- **Flexible CORS policy** — `wildcard`, `reflect` (optionally gated by an
  allow-list), or `explicit` (exact-match allow-list). Preflights short-
  circuit without hitting the upstream and CORS is stamped on errors too.
- **Multi-dimensional rate limiting** — independent GCRA buckets per
  Origin, IP, target host, and process-wide; the first failing dimension
  is attributed via `corx_rate_limited_total{dimension}`.
- **Hardened transport** — optional inbound TLS, mTLS, and FIPS-validated
  crypto via the `tls` / `mtls` / `fips` Cargo features.
- **Production observability** — structured `tracing` access logs,
  Prometheus metrics, and OpenTelemetry / OTLP traces (feature `otel`).
- **Hot reload** — `SIGHUP` atomically swaps every hot-swappable policy
  via `arc-swap`; immutable fields are rejected with a clear log message.
- **Operational endpoints** — `/livez`, `/readyz` (drains to `503` on
  shutdown), `/healthz` alias, and `/iscorsneeded` compatibility shim.

## Quick start

```sh
cargo run --release -p corx-cli -- serve --config corx.example.toml
```

Proxy a request:

```sh
curl -H 'Origin: http://localhost' \
     'http://localhost:8080/https://api.github.com/repos/qntx/corx'
```

Container:

```sh
docker build -t corx:dev .
docker run --rm -p 8080:8080 corx:dev
```

Or boot the full local stack (corx + Prometheus + Grafana + OTLP):

```sh
docker compose up -d
```

## CLI

```sh
corx serve   # default; run the listener
corx check   # validate config, exit non-zero on failure
corx dump    # print the resolved config (--format toml|json)
corx version # print version + os/arch + active features
```

## Configuration

See [`corx.example.toml`](corx.example.toml) for every available setting
and [`docs/configuration.md`](docs/configuration.md) for the reload model.
Configuration sources, in increasing precedence, are:

1. Built-in defaults.
2. `$CORX_CONFIG`, or `./corx.toml`, or `/etc/corx/config.toml`.
3. Environment variables prefixed with `CORX_` (double underscore separates
   nested keys, e.g. `CORX_SERVER__BIND=0.0.0.0:9000`).
4. CLI flags (`--config`).

## Documentation

| Doc                                                | Audience            |
| -------------------------------------------------- | ------------------- |
| [Getting started](docs/getting-started.md)         | New users           |
| [Configuration](docs/configuration.md)             | Operators           |
| [Security model](docs/security.md)                 | Operators / sec-eng |
| [Observability](docs/observability.md)             | SRE / platform      |
| [Operations](docs/operations.md)                   | SRE / on-call       |
| [Deployment](docs/deployment.md)                   | Platform            |
| [Architecture](docs/architecture.md)               | Contributors        |
| [Migration 0.1 -> 0.2](docs/migration.md)          | Upgrade owners      |
| [Testing & benchmarks](docs/testing.md)            | Contributors        |
| [Changelog](CHANGELOG.md)                          | Everyone            |

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
