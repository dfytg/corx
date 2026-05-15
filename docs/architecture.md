# Architecture

## Workspace layout

```text
crates/
├── corx-core/        # framework-agnostic engine
│   ├── config/       # typed TOML + figment loader + validator
│   ├── proxy/        # CORS, SSRF, redirect, URL parser, upstream
│   ├── observability # metric / log / OTLP namespaces
│   └── error.rs      # ProxyError + ErrorKind taxonomy
├── corx-server/      # axum / tower glue
│   ├── handlers      # axum endpoints + proxy fallback
│   ├── middleware    # CORS, load shed, request guard, access log
│   ├── observability # MetricsHandle, OTel layer, CountingBody
│   ├── hot_reload    # SIGHUP + ArcSwap policy snapshot
│   ├── shutdown      # graceful drain + ready flag
│   └── tls (feat)    # axum-server + rustls
└── corx/             # binary: clap subcommands + main.rs
```

`corx-core` has zero `axum` / `tower` dependencies, so it can be reused
under any HTTP framework. `corx-server` is the production binding; the
`corx` binary is a thin shell that owns CLI parsing, logging bootstrap,
and signal wiring.

## Request lifecycle

```text
client request
  → axum router
  → TraceLayer            (per-request span)
  → access_log_layer      (outermost; sees final status)
  → TimeoutLayer
  → DefaultBodyLimit
  → load_shed_layer       (global inflight ceiling)
  → cors_layer            (stamps headers on every response)
  → proxy fallback handler:
      ├── policies = ServerBuild.policies.load()  // ArcSwap snapshot
      ├── if preflight → build_preflight_response → return
      ├── policies.guard.check_origin
      ├── extract_target  // URL parser + IDN punycode + scheme normaliser
      ├── policies.guard.check_rate
      ├── inject Forwarded / X-Forwarded-* / X-Request-Id
      ├── policies.upstream.execute  // hyper-rustls + GuardedResolver
      └── apply_cors + via header → return
```

The whole chain is wait-free: every middleware reads from `Arc`-shared
state or `ArcSwap` snapshots, never holds a lock.

## Hot-reload model

`ServerBuild` splits its state into:

- `policies: Arc<ArcSwap<LivePolicies>>`
  Atomically replaceable on `SIGHUP`; carries `cors`, `request_filter`,
  `response_filter`, `guard`, `upstream`, and the source `Config`.
- `immutable_server` / `immutable_limits` / `immutable_metrics_endpoint`
  Compared against incoming reloads; mismatches are rejected and the
  previous snapshot stays active.

Every handler grabs exactly one snapshot via `state.build.policies()` so
the policy view is internally consistent for the duration of the request.

## Upstream client

`hyper-rustls` over a `HttpConnector` whose resolver is a `GuardedResolver`
wrapping `SsrfGuard`. The guard returns *every* admissible address from a
single DNS lookup so happy-eyeballs IPv4/IPv6 fallback works naturally
while still blocking each candidate against the policy CIDRs.

## Errors

`ProxyError` (in `corx-core`) is the canonical error type. Every variant
maps to:

- A `StatusCode` (`ErrorKind::status`).
- A short slug (`ErrorKind::as_str`) used as the `error` field in JSON
  bodies and as a Prometheus label.

`corx-server` wraps the type in `ServerError` to attach the HTTP envelope
(headers + JSON body + CORS application) without leaking framework details
back into the engine crate.
