# syntax=docker/dockerfile:1.9
#
# Multi-stage build for the `corx` proxy.
#
# * Stage 1 (`chef`)    -- pin cargo-chef, the dependency-graph caching tool.
# * Stage 2 (`planner`) -- emit recipe.json describing the dep graph only.
# * Stage 3 (`builder`) -- cook deps from the recipe, then compile the bin.
# * Stage 4 (`runtime`) -- distroless runtime image, non-root, ~25 MB.
#
# Build arguments:
#   FEATURES        space-separated cargo features to enable on the bin.
#                   Default `""` keeps the image lean (HTTP-only); pass
#                   `"tls mtls otel"` for production TLS + OTLP traces.
#   RUST_VERSION    the rustc toolchain to base the build on.
#
# Multi-arch:
#   `docker buildx build --platform linux/amd64,linux/arm64 ...`
#   The base images (rust + distroless) are multi-arch out of the box; no
#   extra cross-compilation rigging required for these two architectures.

ARG RUST_VERSION=1.94
ARG FEATURES=""

FROM rust:${RUST_VERSION}-slim-bookworm AS chef
ENV CARGO_TERM_COLOR=always
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config build-essential ca-certificates protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG FEATURES
COPY --from=planner /src/recipe.json recipe.json
# Cook deps once; subsequent rebuilds reuse this layer until the dep graph
# (Cargo.toml / Cargo.lock) actually changes.
RUN if [ -n "${FEATURES}" ]; then \
        cargo chef cook --release --recipe-path recipe.json --features "${FEATURES}"; \
    else \
        cargo chef cook --release --recipe-path recipe.json; \
    fi

COPY . .
RUN if [ -n "${FEATURES}" ]; then \
        cargo build --release --locked --bin corx --features "${FEATURES}"; \
    else \
        cargo build --release --locked --bin corx; \
    fi
RUN strip target/release/corx

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
LABEL org.opencontainers.image.title="corx" \
      org.opencontainers.image.description="High-performance CORS forwarding proxy" \
      org.opencontainers.image.source="https://github.com/qntx/corx" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /src/target/release/corx /usr/local/bin/corx
COPY corx.example.toml /etc/corx/config.toml

ENV CORX_CONFIG=/etc/corx/config.toml \
    RUST_LOG=info

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/corx"]
CMD ["serve"]
