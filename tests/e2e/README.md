# dns-rs end-to-end test harness

Drives a real `dns-rs` server process over real DoT/DoH sockets (self-signed
cert, no protocol-layer mocking) to cover things `cargo test` can't: real
upstream connectivity, upstream failure/durability behavior, cache eviction
under pressure, and memory behavior under sustained concurrent load.

## Prerequisites

- `cargo build --release` (the harness runs the release binary)
- `openssl` on `PATH` (used once to generate a local self-signed cert under
  `tests/e2e/certs/`, gitignored)
- `uv` (runs the script with its pinned deps via the PEP 723 header - no venv
  setup needed)
- Outbound network access to a public DoH/DoT resolver (Cloudflare), used for
  the scenarios that need a real, working upstream

## Running

```sh
uv run tests/e2e/harness.py            # everything
uv run tests/e2e/harness.py smoke      # just one scenario
uv run tests/e2e/harness.py cache durability
```

Scenarios: `smoke`, `cache`, `cache-saturation`, `durability`, `memory`,
`dot-limits`.

The memory scenario's duration/concurrency can be overridden:

```sh
E2E_MEMORY_DURATION_S=45 E2E_MEMORY_CONCURRENCY=192 uv run tests/e2e/harness.py memory
```

Each scenario spins its own `dns-rs` subprocess on OS-assigned ports (config
+ logs land under `tests/e2e/.run/<scenario>/`, gitignored) and tears it down
(`SIGINT`, same as Ctrl-C) afterwards. A nonzero exit code means at least one
check failed - see the `Failed checks` list printed at the end.

## What each scenario actually checks

- **smoke** - static hosts bypass upstream, blocklist NXDOMAINs, real upstream
  resolution over both DoT and DoH, malformed queries get FORMERR instead of
  crashing the server, request IDs are correctly patched, pipelined DoT
  queries on one connection each get matched back up correctly.
- **cache** - a cache hit is measurably faster than the miss that populated
  it, carries the *new* request's ID, and returns byte-identical answer data.
- **cache-saturation** - a deliberately tiny cache pool (3 KiB) under 150
  unique queries: eviction actually triggers (checked via log lines), the
  server survives, and a long-evicted name still resolves correctly on
  re-query instead of returning something stale/wrong.
- **durability** - the shared-deadline fallback logic in `dns::upstream`:
  fast-failing dead upstreams fall through to a working one quickly; a
  *hung* upstream bounds total latency to ~1x `UPSTREAM_TIMEOUT` instead of
  blowing past it (the core regression check for that fix), with the
  side-effect documented that a hung upstream in first position starves the
  fallback within that single query; `race` strategy shrugs off the same
  hung upstream by querying concurrently instead of sequentially; all-dead
  returns SERVFAIL, still bounded, never silence and never a hang.
- **memory** - sustained high-concurrency mixed DoT/DoH load (cache hits +
  genuine upstream misses), sampling the server's RSS throughout. Looks for
  a leak-shaped curve (still climbing hard in the final third of the run)
  vs. the expected warm-up-then-plateau shape. This is a smoke signal from
  one short burst, not a substitute for a real longevity/soak test. Its DoT
  worker always sends a complete query and closes promptly - it does not
  cover a connection that just sits there, which is what `dot-limits` is for.
- **dot-limits** - the DoT connection cap and idle-timeout reaping
  (`server/dot.rs`'s `MAX_CONCURRENT_CONNECTIONS`/`IDLE_TIMEOUT`), covering
  the actual pattern that motivated them: a connection that completes a TLS
  handshake and then never sends a query, same as internet background
  scanners hitting port 853 do in practice. Opening well past the cap gets
  the excess rejected immediately (not queued) while the server keeps
  serving real queries throughout; a handful of connections left
  deliberately silent get closed on their own within `IDLE_TIMEOUT`, and the
  server is confirmed still healthy and responsive afterward. Slow (~2.5
  min) by design - it waits out the real timeout rather than mocking it.
