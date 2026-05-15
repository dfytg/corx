# Security model

`corx` is designed to be safe to expose to the open internet. Every layer
defaults to the strictest setting that still allows the cors-anywhere use
case to function.

## Defence layers

```text
   client
     │
     ▼
+---------+   1. TLS / mTLS (feature `tls` / `mtls`)
| listener|
+---------+
     │
     ▼
+---------+   2. Body / header size limits
| router  |   3. Timeouts
+---------+   4. Load shed (global inflight cap)
     │
     ▼
+---------+   5. CORS preflight short-circuit
| guards  |   6. Origin allow/deny + required headers
+---------+   7. Multi-dimensional rate limit
     │
     ▼
+---------+   8. URL parser (RFC 3986 + scheme normaliser)
| target  |   9. SSRF guard (DNS-aware, IPv4-mapped canonicalisation)
+---------+   10. Redirect guard (max hops, https-to-http downgrade gate)
     │
     ▼
+---------+   11. Outbound HTTP client (rustls / aws-lc-rs)
| upstream|
+---------+
```

## SSRF guard

The guard sits **between** the URL parser and hyper's connector, so it is
impossible to bypass by aiming the proxy at an IP literal:

- Default block-list covers RFC 1918, loopback, link-local (incl. cloud
  metadata), and IPv6 reserved ranges.
- IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are folded back to IPv4
  before evaluation.
- Operators add carve-outs via `ssrf.extra_allowed_cidrs`; they take
  precedence and are how you intentionally proxy to internal API gateways.
- `ssrf.deny_redirect_to_private = true` (default) extends the same checks
  to every hop in a redirect chain.

## CORS policy

- `wildcard` returns `Access-Control-Allow-Origin: *`.
- `reflect` (default) echoes the request `Origin`, optionally constrained
  by `cors.allowlist`.
- `explicit` returns the request `Origin` only if it is on `cors.explicit`.

`allow_credentials = true` automatically downgrades wildcard mode to
reflection because browsers reject `*` together with credentials.

CORS headers are also stamped on **error** responses so browsers can read
the JSON error body.

## Origin allow/deny lists

`security.origin_blacklist` and `origin_whitelist` are exact-match string
lists evaluated before the rate limiter, so blocked origins never burn
through limit budget.

## Rate limit dimensions

Each dimension is an independent GCRA bucket. The first dimension to fail
is the one Prometheus attributes the rejection to via
`corx_rate_limited_total{dimension}`:

- `origin` (per `Origin` header)
- `ip` (per remote address; CIDRs in `trusted_cidrs` are exempted)
- `target_host` (per validated upstream host)
- `global` (process-wide), backed by an inflight gauge for load shed

## TLS / mTLS / FIPS

The optional `tls`, `mtls`, and `fips` Cargo features compile in inbound
TLS termination, mutual-TLS verification, and the aws-lc-rs FIPS-validated
crypto provider respectively. See
[`docs/deployment.md`](deployment.md#tls) for the full operator workflow.

## Header hygiene

By default `corx` strips `cookie` / `cookie2` from inbound requests and
`set-cookie` / `set-cookie2` from upstream responses, eliminating an entire
class of CSRF vectors. Tweak `security.remove_request_headers` and
`security.remove_response_headers` for additional fields.
