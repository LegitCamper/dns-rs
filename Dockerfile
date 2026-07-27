# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder

# aws-lc-sys (rustls' crypto backend) builds a vendored C library via cmake.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build dependencies first, separately from our own source, so editing
# src/ doesn't invalidate the (much slower) dependency-compilation layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs \
    && cargo build --release \
    && strip target/release/dns-rs

FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for outbound HTTPS (blocklist downloads, DoH upstream).
# libcap2-bin: lets the binary bind privileged ports (853/443) without running as root.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dns-rs

COPY --from=builder /build/target/release/dns-rs /usr/local/bin/dns-rs
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/dns-rs

USER dns-rs
WORKDIR /etc/dns-rs

EXPOSE 853/tcp 443/tcp

ENTRYPOINT ["/usr/local/bin/dns-rs"]
CMD ["--config", "/etc/dns-rs/config.toml"]
