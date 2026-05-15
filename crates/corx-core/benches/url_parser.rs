//! Microbenchmarks for `corx_core::proxy::extract_target`.
//!
//! `extract_target` runs on every request that reaches the proxy fallback
//! handler, so we keep a couple of representative shapes pinned to detect
//! regressions: scheme-less hosts, full URLs, query-string targets, and
//! punycode IDNs.

use corx_core::proxy::extract_target;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::Uri;

fn bench_extract_target(c: &mut Criterion) {
    let mut group = c.benchmark_group("extract_target");

    let cases: &[(&str, &str)] = &[
        ("schemeless_host", "/example.com/path?x=1"),
        ("full_https_url", "/https://api.example.com/v1/users?id=42"),
        (
            "query_string_form",
            "/?url=https%3A%2F%2Fapi.example.com%2Fv1%2Fitems",
        ),
        (
            "punycode_idn",
            "/https://xn--80ak6aa92e.example.com/path",
        ),
        (
            "deep_path",
            "/https://example.com/a/b/c/d/e/f/g/h/i/j?token=deadbeef&page=7",
        ),
    ];

    for (name, raw) in cases {
        let uri: Uri = raw.parse().expect("uri");
        group.bench_function(*name, |b| {
            b.iter(|| {
                let _ = black_box(extract_target(black_box(&uri)));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_extract_target);
criterion_main!(benches);
