# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder

# aws-lc-sys (rustls' crypto backend) builds a vendored C library via cmake.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# cargo-sonic (https://github.com/glebpom/cargo-sonic) builds this project
# once per listed --target-cpus level and bundles all of them into one
# binary; a small runtime loader picks the best match for the actual host's
# CPU at startup, falling back to the plain x86-64 baseline (always built
# automatically) on anything older. Installed in its own layer so it isn't
# rebuilt every time our own source changes. This roughly multiplies build
# time by the number of variants (each is a full, separately-LTO'd build).
RUN cargo install --locked cargo-sonic

WORKDIR /build

# Build dependencies first, separately from our own source, so editing
# src/ doesn't invalidate the (much slower) dependency-compilation layer.
# This now compiles the dependency graph once per listed CPU variant, plus
# the always-included baseline.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo sonic --target-cpus=x86-64-v2,x86-64-v3,x86-64-v4 --loader=bundle build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs \
    && cargo sonic --target-cpus=x86-64-v2,x86-64-v3,x86-64-v4 --loader=bundle build --release

FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for outbound HTTPS (blocklist downloads, DoH upstream).
# libcap2-bin: lets the binaries bind privileged ports (853/443) without running as root.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dns-rs

# --loader=bundle output is a small launcher plus a sibling
# <bin-name>.bundle/ directory of per-CPU payload binaries; both must be
# copied and kept adjacent. Uncompressed bundle payloads are exec'd
# directly from their on-disk file (verified: the running process's own
# /proc/self/exe reports the payload's real path, not a copied-into-memory
# one) rather than the launcher itself, so the capability grant has to go
# on every payload file, not just the launcher.
COPY --from=builder /build/target/sonic/x86_64-unknown-linux-gnu/release/dns-rs /usr/local/bin/dns-rs
COPY --from=builder /build/target/sonic/x86_64-unknown-linux-gnu/release/dns-rs.bundle /usr/local/bin/dns-rs.bundle
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/dns-rs \
    && for f in /usr/local/bin/dns-rs.bundle/*.elf; do setcap 'cap_net_bind_service=+ep' "$f"; done

USER dns-rs
WORKDIR /etc/dns-rs

EXPOSE 853/tcp 443/tcp

ENTRYPOINT ["/usr/local/bin/dns-rs"]
CMD ["--config", "/etc/dns-rs/config.toml"]
