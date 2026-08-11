# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A small DNS resolver that only speaks encrypted transports — DNS-over-TLS
(RFC 7858) and DNS-over-HTTPS (RFC 8484) — with blocklist-based adblocking.
There is no plaintext UDP/TCP port 53 listener. Built for a home network /
single small box, not to compete with BIND/Unbound/CoreDNS at scale.

## Commands

```sh
cargo build --release
cargo test                       # unit + integration tests, no network required
cargo test <test_name>           # run a single test by name (substring match)
cargo test --lib dns::handler    # run a module's tests, e.g. src/dns/handler.rs
cargo clippy --all-targets
./target/release/dns-rs --config /path/to/config.toml
```

Unit/integration tests live inline in `#[cfg(test)] mod tests` blocks at the
bottom of the relevant source file (`blocklist.rs`, `util.rs`,
`dns/{cache,handler,upstream}.rs`) — grep for `mod tests` to find them
rather than looking under `tests/`.

End-to-end tests (`tests/e2e/`) drive a real release binary over real
DoT/DoH sockets and are **not** run by `cargo test`:

```sh
cargo build --release
uv run tests/e2e/harness.py            # everything
uv run tests/e2e/harness.py smoke      # one scenario: smoke, cache, cache-saturation, durability, memory
```

They need `openssl` (generates a self-signed cert under `tests/e2e/certs/`,
gitignored) and outbound network access to a public resolver (Cloudflare).
See `tests/e2e/README.md` for what each scenario actually checks — it's
detailed and worth reading before touching cache eviction, upstream
fallback/race, or the DoT/DoH listeners.

Binding to the default ports (853/443) needs root or
`cap_net_bind_service`; remap `dot_port`/`doh_port` in `config.toml` to high
ports for local runs instead.

## Architecture

Request flow (`src/dns/handler.rs::resolve`), checked in this order for
every query, static hosts → cache → blocklist → upstream (with in-flight
dedup):

1. **Static hosts** (`state.rs`) — config-defined domain→IP, checked first,
   never forwarded upstream, only `A` is synthesized (no IPv6).
2. **Response cache** (`dns/cache.rs`) — one fixed-size byte-budgeted arena
   allocated once at startup (`linked_list_allocator::Heap`), with
   individual responses suballocated from it rather than a fixed-size
   per-entry slot. Full cache evicts expired entries first, then LRU. A
   background sweeper also reclaims expired entries on a timer
   (`SWEEP_INTERVAL`). RFC 2308 negative caching (NXDOMAIN/NODATA) is
   supported when the upstream response has an SOA to bound the TTL — see
   `negative_ttl` in `handler.rs`.
3. **Blocklist** (`blocklist.rs`) — an `ArcSwap<FxHashSet<String>>`
   (`BlockSet`) for lock-free hot reads. `BlocklistManager` maintains two
   independent `DomainSet`s (blocklist, whitelist), each a union of inline
   config domains + N URL sources refreshed on their own timers; the
   published `BlockSet` is recomputed as (blocklist ∖ whitelist) any time
   either side's sources refresh, so a background blocklist refresh can
   never silently re-block a whitelisted domain. Supports hosts-file,
   plain-domain-per-line, and Adblock Plus (`||domain^`) formats; cosmetic
   Adblock rules (`##`/`#@#`/`#?#`) are deliberately ignored, not
   mis-parsed.
4. **Upstream** (`dns/upstream.rs`) — `MultiUpstream<U>` over the
   `Upstream` trait, generic so tests substitute a network-free fake
   (`dns/test_support.rs::TestUpstream`); production uses `SingleUpstream`
   (DoT via a 1-deep idle connection pool per upstream, or DoH via
   `reqwest`). Two strategies: `sequential` (ordered fallback, one request
   at a time) or `race` (`futures_util::select_ok`, query all upstreams
   concurrently). Concurrent identical cache-miss queries are coalesced by
   `dns/inflight.rs::InFlightRegistry` (keyed on qname/qtype/qclass) into a
   single upstream fetch via `tokio::sync::OnceCell` — every caller still
   patches its own request ID onto the shared response.

`AppState<U: Upstream = SingleUpstream>` (`state.rs`) bundles all of the
above and is handed by `Arc` to every connection handler; it's generic over
`Upstream` purely so `handle_query` and its tests can run against
`TestUpstream` with no real sockets/TLS.

**Listeners** (`server/dot.rs`, `server/doh.rs`) both funnel into the same
`dns::handler::handle_query`. DoT is a length-prefixed (RFC 7858) framing
loop where each pipelined query on a connection runs in its own task
(bounded by `MAX_CONCURRENT_QUERIES_PER_CONNECTION`), with a single writer
task serializing socket writes — responses can complete out of order, same
as any pipelined DNS-over-TCP server. DoH is an `axum`/`axum-server` router
supporting both GET (`?dns=`) and POST forms of RFC 8484, with HTTP/2
rapid-reset mitigation tuned looser than h2's default (see comments in
`doh.rs`) so legitimate concurrent load doesn't trip it.

**Config & reload** (`main.rs`, `config.rs`): the config file is polled
(not inotify — deliberately, for correctness across atomic-rename writes)
every `CONFIG_POLL_INTERVAL`. A changed file triggers a full state rebuild
and listener restart behind a `CancellationToken`, with in-flight DoT/DoH
requests getting a grace period before old listeners are torn down — the
process never restarts and never drops already-accepted connections
abruptly.

**TLS** (`tls.rs`): DoT loads its `rustls::ServerConfig` here; DoH uses
axum-server's own PEM loader instead (`server/doh.rs`) — same cert/key
files, two different loading paths since DoT and DoH use different TLS
stacks. Both listeners require a TLS cert/key regardless of deployment; the
project deliberately never serves plaintext DNS as a fallback.

## Known constraints (by design, not gaps to silently "fix")

- No DNSSEC validation, no IPv6 synthesis (static hosts / sinkhole only
  ever produce `A` records), no query ACLs, single-process/no clustering.
- Blocklist/cache use non-cryptographic hashing (`rustc-hash`) for
  per-query speed — an accepted tradeoff for a personal/home resolver, not
  an oversight.

## Rules

- Don't use `pub use` for convenient usage **within** the crate
- Don't add a small helper function (≤ 10 lines) that has only one call site — inline it at the call site
- When writing code comments, follow the principles in [Best practices for writing code comments](https://stackoverflow.blog/2021/12/23/best-practices-for-writing-code-comments/)
- When writing documentation and READMEs, follow the principles in [Best practices for GitHub Docs](https://docs.github.com/en/contributing/writing-for-github-docs/best-practices-for-github-docs)
- If you need a paragraph-long comment to justify why the workaround is OK, the code is wrong — fix the code.
