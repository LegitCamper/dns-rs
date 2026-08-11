# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder

# Populated automatically by buildx for each platform in a multi-platform
# build (this image is built for linux/amd64 and linux/arm64 - see
# .github/workflows/docker.yml).
ARG TARGETARCH

# aws-lc-sys (rustls' crypto backend) builds a vendored C library via cmake.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# cargo-sonic (https://github.com/glebpom/cargo-sonic) builds this project
# once per listed --target-cpus level and bundles all of them into one
# binary; a small runtime loader picks the best match for the actual host's
# CPU at startup, falling back to the plain x86-64 baseline (always built
# automatically) on anything older.
#
# amd64 only: cargo-sonic requires at least one --target-cpus value, and
# x86-64 has well-defined, portable generic microarchitecture levels
# (v2/v3/v4) to list. arm64 doesn't have an equivalent generic ladder - ARM
# target-cpu values are vendor/chip-specific (e.g. neoverse-n1, apple-m1),
# not safely portable across arbitrary arm64 hardware the way x86-64-vN is
# across x86 hardware - so arm64 just gets a normal single-variant build.
# Installed in its own layer so it isn't rebuilt every time our own source
# changes.
RUN if [ "$TARGETARCH" = "amd64" ]; then cargo install --locked cargo-sonic; fi

WORKDIR /build

# Build dependencies first, separately from our own source, so editing
# src/ doesn't invalidate the (much slower) dependency-compilation layer.
# On amd64 this compiles the dependency graph once per listed CPU variant,
# plus the always-included baseline.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && if [ "$TARGETARCH" = "amd64" ]; then \
         cargo sonic --target-cpus=x86-64-v2,x86-64-v3,x86-64-v4 --loader=bundle build --release; \
       else \
         cargo build --release; \
       fi \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs \
    && if [ "$TARGETARCH" = "amd64" ]; then \
         cargo sonic --target-cpus=x86-64-v2,x86-64-v3,x86-64-v4 --loader=bundle build --release; \
       else \
         cargo build --release; \
       fi

# Normalize into a fixed path regardless of which branch above ran, so the
# runtime stage doesn't need to know or care which one produced it.
# --loader=bundle output (amd64) is a small launcher plus a sibling
# <bin-name>.bundle/ directory of per-CPU payload binaries - both are
# needed, kept adjacent, exactly as cargo-sonic produced them.
RUN mkdir -p /build/output \
    && if [ "$TARGETARCH" = "amd64" ]; then \
         cp target/sonic/x86_64-unknown-linux-gnu/release/dns-rs /build/output/dns-rs; \
         cp -r target/sonic/x86_64-unknown-linux-gnu/release/dns-rs.bundle /build/output/dns-rs.bundle; \
       else \
         cp target/release/dns-rs /build/output/dns-rs; \
       fi

FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for outbound HTTPS (blocklist downloads, DoH upstream).
# libcap2-bin: lets the binaries bind privileged ports (853/443) without running as root.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dns-rs

COPY --from=builder /build/output/ /usr/local/bin/

# Uncompressed bundle payloads are exec'd directly from their on-disk file
# (verified: the running process's own /proc/self/exe reports the payload's
# real path, not a copied-into-memory one) rather than the launcher itself,
# so the capability grant has to go on every payload file, not just the
# launcher. Each payload lives in its own per-CPU subdirectory (e.g.
# dns-rs.bundle/x86-64-v3/dns-rs), not flat inside dns-rs.bundle/ - `find`
# instead of a glob so this doesn't care about that nesting or naming.
# No-op on arm64, where there's no dns-rs.bundle/ directory.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/dns-rs \
    && if [ -d /usr/local/bin/dns-rs.bundle ]; then \
         find /usr/local/bin/dns-rs.bundle -type f -exec setcap 'cap_net_bind_service=+ep' {} \; ; \
       fi

USER dns-rs
WORKDIR /etc/dns-rs

EXPOSE 853/tcp 443/tcp

ENTRYPOINT ["/usr/local/bin/dns-rs"]
CMD ["--config", "/etc/dns-rs/config.toml"]
