#![allow(
    unused_crate_dependencies,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::let_underscore_must_use,
    reason = "See the sibling `url_parser.rs` bench for the rationale."
)]

//! Microbenchmark for `SsrfGuard::check_ip`.
//!
//! The guard runs synchronously inside the hyper resolver path, so its
//! decision throughput directly bounds the proxy's request rate when
//! upstream connection reuse is cold. This bench only exercises the IP
//! literal path because the DNS-resolved code path is dominated by the
//! resolver's own cost.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corx_core::config::{SsrfConfig, SsrfMode};
use corx_core::proxy::{SsrfGuard, build_resolver};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn make_guard(mode: SsrfMode) -> SsrfGuard {
    let cfg = SsrfConfig {
        mode,
        allow_ipv6: true,
        extra_blocked_cidrs: Vec::new(),
        extra_allowed_cidrs: Vec::new(),
        deny_redirect_to_private: true,
    };
    SsrfGuard::new(&cfg, build_resolver())
}

fn bench_check_ip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssrf_check_ip");

    let strict = make_guard(SsrfMode::Strict);
    let permissive = make_guard(SsrfMode::Permissive {
        allow_private: false,
    });

    let cases: &[(&str, IpAddr)] = &[
        ("public_ipv4", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ("loopback_ipv4", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        (
            "link_local_ipv4",
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ),
        (
            "public_ipv6",
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
        ),
        ("loopback_ipv6", IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];

    for (name, ip) in cases {
        group.bench_function(format!("strict::{name}"), |b| {
            b.iter(|| {
                let _ = black_box(strict.check_ip(black_box(*ip)));
            });
        });
        group.bench_function(format!("permissive::{name}"), |b| {
            b.iter(|| {
                let _ = black_box(permissive.check_ip(black_box(*ip)));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_check_ip);
criterion_main!(benches);
