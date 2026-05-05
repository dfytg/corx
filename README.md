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
  allow-list) or `explicit` (exact-match allow-list). Preflights are handled
  without hitting the upstream.
- **Manual redirect following** — cross-host redirects strip sensitive
  headers and drop bodies that cannot be safely replayed.
- **First-class observability** — structured `tracing` logs (JSON or
  pretty), Prometheus metrics served under `/metrics`.
- **Per-origin rate limiting** — GCRA token bucket powered by `governor`,
  optional regex allow-list for unlimited origins.
- **Operational endpoints** — `/healthz` liveness probe and
  `/iscorsneeded` compatibility shim for cors-anywhere clients.

## Quick start

```sh
cargo run --release --bin corx -- --config corx.example.toml
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

## Configuration

See `corx.example.toml` for every available setting. Configuration sources,
in increasing precedence, are:

1. Built-in defaults.
2. `$CORX_CONFIG`, or `./corx.toml`, or `/etc/corx/config.toml`.
3. Environment variables prefixed with `CORX_` (double underscore separates
   nested keys, e.g. `CORX_SERVER__BIND=0.0.0.0:9000`).
4. CLI flags (`--config`).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QNTX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QNTX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx-banner.svg" /></a>

<!--prettier-ignore-->
Code is law. We write both.

</div>
