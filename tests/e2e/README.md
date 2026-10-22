# dns-rs end-to-end test harness

Drives a real `dns-rs` server process over real DoT/DoH sockets (self-signed
cert, no protocol-layer mocking) to cover things `cargo test` can't: real
upstream connectivity, upstream failure/durability behavior, cache eviction
under pressure, and memory behavior under sustained concurrent load.

## Prerequisites

- `cargo build --release` (the harness runs the release binary; override with
  `DNSRS_E2E_BINARY=/path/to/dns-rs`)
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
`dot-limits`, `perf-local`, `perf-live`. Measurement scenarios are opt-in and
are not included by `all`.

## Performance measurement

For tail-latency changes, `perf_tail.py` uses certificate-verified local DoH
upstreams with controlled delays and a persistent client DoT connection. No
public DNS traffic or host trust-store changes. It compares eight A-B-B-A
rounds, excludes client TLS setup, and saves raw samples and binary hashes:

```sh
# Preserve the old release binary before building the changes.
mkdir -p tests/e2e/.run/latency
cp target/release/dns-rs tests/e2e/.run/latency/baseline
cargo build --release --locked
uv run tests/e2e/perf_tail.py \
  --baseline tests/e2e/.run/latency/baseline \
  --candidate target/release/dns-rs \
  --rounds 8 --requests 1000 --sweep-entries 50000 --blocklist-entries 250000
```

Hot hits and ordinary misses use identical configuration. The slow-primary
scenario compares the baseline's `sequential` deployment setting with the
candidate's `hedged` setting (80 ms primary, 12 ms fallback). This measures the
configuration change as well as code; it is not evidence of a faster parser.
The idle probe queries four reused names after 33 seconds, beyond their
two-second TTL plus 30-second stale window, and records background traffic.
This small probe demonstrates avoided misses; its four samples do not establish
a stable p99. Optional sweep probes fill a 64 MiB cache with 50,000 short-lived
entries and measure static responses across two sweep intervals.
The blocklist probe rebuilds 250,000 domains every five seconds while measuring
static responses; on Linux it pins the DNS process to one CPU. Use `--rounds 0`
to repeat only probes, and `--skip-idle` to omit the 33-second waits.

Results land in `tests/e2e/.run/latency/perf-tail.json`; server logs are under
`tests/e2e/.run/tail-*/server.log`. Loopback latency includes the Python client,
fixture and OS scheduling. It does not predict Android/Fly network latency.
Run without other builds or load tests competing for CPU.

To compare upstream strategies without changing production configuration:

```sh
uv run tests/e2e/perf_tail.py \
  --baseline target/release/dns-rs --candidate target/release/dns-rs \
  --compare-strategies --skip-idle --rounds 8 --requests 1000 \
  --output tests/e2e/.run/latency/strategies.json
```

Here `baseline` means `hedged` and `candidate` means `race`, using the same
binary. Four local HTTPS/HTTP/1.1 upstreams delay answers by 12, 18, 30 and
80 milliseconds. The healthy-primary order starts with the fastest upstream;
the slow-primary order starts with the slowest. Each slot measures 1000
warmed hits and 80 unique misses per order,
and counts upstream requests for those misses. Results isolate scheduling
under controlled delays, not public resolver performance or HTTP/2 behavior.

An independent opt-in experiment exercises real TLS/HTTP/2 DoH reconnection:

```sh
cargo test --release --locked benchmark_doh_rewarm -- --ignored --nocapture
```

Across 64 alternating pairs, it establishes a pooled connection, shuts down
the upstream, restarts it at the same address, and measures the next query
with or without a preceding root-NS warm probe. The fixture delays TLS
acceptance by 40 milliseconds and answers by 12 milliseconds. Both delays
are artificial. Assertions require HTTP/2,
successful DNS validation, and exactly one replacement connection reused by
the warmed query. `DOH_REWARM_RESULT` contains raw timings, including probe
cost. This tests the warm primitive, not a periodic production scheduler or
silent network blackholes; report medians rather than treating 64 samples as
a stable p99. Run separately from the strategy benchmark.

Performance runs are opt-in. They reuse one multiplexed TLS connection per DoT
target and one persistent HTTP/1.1 `httpx.AsyncClient` per DoH target. TLS setup
is recorded separately and excluded from steady-state samples. Measured local
servers use `RUST_LOG=warn`; correctness scenarios keep existing log defaults.

Build baseline and candidate with identical locked inputs. An exact committed
baseline can be exported without touching dirty source:

```sh
REV=9e9d56419452b822e226c3e7f6f8329f8fd244b2
mkdir -p tests/e2e/.run/builds/baseline-src
git archive "$REV" | tar -x -C tests/e2e/.run/builds/baseline-src
CARGO_INCREMENTAL=0 cargo build --release --locked \
  --manifest-path tests/e2e/.run/builds/baseline-src/Cargo.toml \
  --target-dir tests/e2e/.run/builds/baseline-target
CARGO_INCREMENTAL=0 cargo build --release --locked \
  --target-dir tests/e2e/.run/builds/candidate-target
```

Run one binary or an eight-round paired A-B-B-A comparison:

```sh
uv run tests/e2e/harness.py perf-local \
  --binary-a tests/e2e/.run/builds/baseline-target/release/dns-rs \
  --rounds 1 --requests 50 --warmup 10 --seed 20260413

uv run tests/e2e/harness.py perf-local \
  --binary-a tests/e2e/.run/builds/baseline-target/release/dns-rs \
  --binary-b tests/e2e/.run/builds/candidate-target/release/dns-rs \
  --label-a baseline --label-b candidate \
  --rounds 8 --requests 200 --warmup 20 --concurrency 8 \
  --seed 20260413 --output tests/e2e/.run/perf-local.json
```

Each logical paired round starts fresh processes in A-B-B-A order, reversing
outer/inner labels on alternating rounds. Warmups, startup, and TLS setup do not
enter latency samples. Workloads cover static and blocked responses, hot positive
and negative cache entries, unique negative misses, seeded mixed traffic,
concurrent identical misses, and a `sweep-over-30s` mixed probe whose default
31-second window crosses the cache sweep interval. Every response is validated
for ID, question, rcode, decoding, and expected static answer. Local runs repeat
against Cloudflare DoH only, Cloudflare DoT only, current sequential list, and
hedged list.

Public comparison is deliberately bounded to one request/second aggregate across
DoT and DoH:

```sh
uv run tests/e2e/harness.py perf-live \
  --rounds 8 --requests 10 --live-rate 1 \
  --fly-host dns-rs-cold-hollow-7445.fly.dev \
  --output tests/e2e/.run/perf-live.json
```

`--fly-doh-url`, `--cloudflare-dot-host`, and `--cloudflare-doh-url` override
endpoints. Live mode compares current Fly and direct Cloudflare separately for
DoT and DoH. It does not require a local binary or mutate Fly state.

JSON evidence contains raw per-request samples, p50/p90/p95/p99/max, QPS,
errors/timeouts/validation failures, process CPU and RSS when `/proc` exists,
connection policy, HTTP versions, server exits, seed/workload settings, Git
state, binary path/size/SHA-256, toolchain, OS/CPU, build profile/features/flags,
and profiler availability. Default output is under ignored
`tests/e2e/.run/perf-*.json`.

Retain an optimization only when at least six of eight paired rounds show a
>=5% affected latency, CPU/query, or QPS improvement, with no response mismatch,
error increase, added upstream behavior, or >5% p99 regression. Static/hot gaps
mostly isolate inbound processing and placement overhead; miss gaps include the
extra upstream RTT. Public-network deltas are not evidence of Rust-only cost.
When `perf` is unavailable, `/proc` metrics remain process-wide and cannot prove
function-level lock attribution.

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
