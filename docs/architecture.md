# Architecture

## Workspace layout

```text
crates/
├── corx-core/        # framework-agnostic engine
│   ├── config/       # typed config + validator (no IO)
│   ├── policy/       # TargetPolicy, CircuitBreaker
│   ├── proxy/        # CORS, SSRF, redirect, URL parser, upstream
│   ├── observability # metric name constants
│   └── error.rs      # ProxyError + ErrorKind taxonomy
├── corx-server/      # axum / tower glue
│   ├── handlers      # axum endpoints + proxy fallback
│   ├── middleware    # CORS, load shed, auth, access log
│   ├── observability # MetricsHandle, OTel layer, CountingBody
│   ├── hot_reload    # SIGHUP + ArcSwap policy snapshot
│   ├── shutdown      # graceful drain + ready flag
│   └── tls (feat)    # axum-server + rustls
├── corx/             # umbrella library (recommended embed API)
└── corx-cli/         # binary package; [[bin]] name = "corx"
```

**Dependency direction:** `corx-cli` → `corx` → (`corx-server` → `corx-core`).

`corx-core` has zero `axum` dependencies and only the minimal
`tower-service` trait (for hyper's custom DNS resolver). Policy engines
live in core so they can be unit-tested without a server. `corx-server`
is the production axum/tower binding. `corx` re-exports both for
embedders. `corx-cli` is a thin shell that owns CLI parsing, logging
bootstrap, and signal wiring; the installed binary remains named `corx`.

## Request lifecycle

```text
client request
  → axum router
  → TraceLayer            (per-request span)
  → access_log_layer      (outermost; sees final status)
  → TimeoutLayer
  → DefaultBodyLimit
  → header_limit_layer    (max_request_header_bytes → 431)
  → load_shed_layer       (global inflight ceiling)
  → cors_layer            (stamps headers on every response)
  → proxy fallback handler:
      ├── policies = ServerBuild.policies.load()  // ArcSwap snapshot
      ├── if preflight:
      │     ├── (default) origin guard + optional rate limit
      │     └── build_preflight_response → return
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
