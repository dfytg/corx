# syntax=docker/dockerfile:1.7

# --------------------------------------------------------------------------
# Build stage — compile a fully static binary with cargo + musl.
# --------------------------------------------------------------------------
FROM rust:1.94-slim-bookworm AS build

ARG TARGETARCH
ENV CARGO_TERM_COLOR=always

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Leverage Docker layer caching for dependency compilation.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY corx/Cargo.toml corx/Cargo.toml
RUN mkdir -p corx/src \
 && echo 'fn main() {}' > corx/src/main.rs \
 && echo '' > corx/src/lib.rs \
 && cargo build --release --locked --bin corx \
 && rm -rf corx/src target/release/deps/corx*

# Now compile the real source.
COPY corx/src corx/src
RUN cargo build --release --locked --bin corx \
 && strip target/release/corx

# --------------------------------------------------------------------------
# Runtime stage — minimal distroless image for security.
# --------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=build /src/target/release/corx /usr/local/bin/corx
COPY corx.example.toml /etc/corx/config.toml

ENV CORX_CONFIG=/etc/corx/config.toml

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/corx"]
