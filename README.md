# dns-rs

A small DNS resolver that only speaks encrypted transports — DNS-over-TLS
([RFC 7858](https://www.rfc-editor.org/rfc/rfc7858)) and DNS-over-HTTPS
([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)) — with blocklist-based
adblocking bolted on. There's no plaintext UDP/TCP port 53 listener; every
query in and every query out is TLS.

This exists to run on a home network or a single small box, in front of
a couple of clients, not to compete with BIND/Unbound/CoreDNS at scale.
It hasn't been fuzzed, load-tested, or security-reviewed by anyone other
than its author. Read the code before you point production traffic at it.

## What it actually does

- **DoT + DoH only.** Clients (or your router) point at this instead of your
  ISP's resolver or your VPN provider's, and both the query and the answer
  are encrypted on the wire — no plaintext resolver in the path can see or
  tamper with lookups.
- **Blocklists**, fetched over HTTP(S) on a configurable interval, parsed as
  hosts-file format, plain domain-per-line, or Adblock Plus network rules
  (`||domain^`). Cosmetic Adblock rules (`##`, `#@#`, `#?#`) are recognized
  and deliberately ignored rather than mis-parsed into blocked domains — a
  bug in an earlier version of the parser did the opposite and NXDOMAIN'd
  half the web.
- **A whitelist** of exact domains that override every blocklist, checked
  every time the merged list is rebuilt so a background refresh can't
  silently re-block something you carved out.
- **Static host overrides** — your own domain → IP entries, checked before
  the blocklist and never forwarded upstream.
- **Blocking modes**: NXDOMAIN (domain doesn't exist) or sinkhole (resolves
  to an IP you configure, the classic Pi-hole style).
- **A response cache** sized in bytes, not entry count. It's one
  fixed-size arena allocated once at startup; individual responses are
  suballocated out of it via a first-fit allocator with free-block
  coalescing, so a cache full of tiny NXDOMAINs and a cache full of large
  TXT records both just use however many bytes they actually need. When
  it's full, expired entries are evicted first, then least-recently-used
  ones. A background sweeper also reclaims expired entries on a timer so a
  live request doesn't usually have to do that cleanup itself.
- **RFC 2308 negative caching** — NXDOMAIN and NODATA responses are cached
  too, when the upstream provides an SOA record to bound how long that's
  safe to assume.
- **Two upstream strategies**: sequential fallback (try each configured
  upstream in order) or race (query all of them, take whichever answers
  first). Duplicate in-flight queries for the same name/type are coalesced
  into a single upstream request.
- **Hot config reload** — the config file is polled for changes and a
  changed file is reloaded without dropping the process or existing
  connections (in-flight requests get a grace period before the old
  listeners are torn down).

## What it doesn't do

- No plaintext DNS on port 53 (UDP or TCP). If something on your network
  only speaks classic DNS, it needs a client-side proxy (e.g. `stubby`,
  `dnscrypt-proxy`) in front of this, not the other way around.
- No DNSSEC validation.
- No IPv6 in synthesized answers (static hosts and sinkhole mode only ever
  produce `A` records; `AAAA` queries against those names get NOERROR/NODATA,
  which still blocks them, just without a synthesized IPv6 sinkhole address).
- Single process, single cache, no clustering or shared state between
  instances — if you want redundancy, run two independent instances behind
  DNS-level failover, not two instances sharing state.
- No query ACLs / authentication. Anything that can reach the configured
  ports can query it. Firewall it like you would any other internal service.

## Configuration

Copy `config.example.toml` to `config.toml` (or point `--config` at wherever
you keep it) and edit it — every option is commented there, including the
tradeoffs on cache sizing and upstream strategy. The broad shape:

```toml
[server]        # bind address, DoT/DoH ports, TLS cert/key paths
[blocking]      # nxdomain or sinkhole, and the sinkhole IP
[blocklists]    # URLs to fetch, refresh interval
[whitelist]     # domains blocklists may never block
[upstream]      # DoT/DoH upstream resolvers, sequential or race
[static_hosts]  # your own domain -> IP overrides
[cache]         # enabled + total byte budget
```

You need a TLS certificate and key regardless of deployment method — both
listeners require one. A self-signed cert is fine for a home network as
long as your clients are configured to trust it; a real cert (e.g. from a
DNS-validated ACME issuance) works too if the resolver has a public name.

## Running it

### From source

```sh
cargo build --release
./target/release/dns-rs --config /path/to/config.toml
```

Binding to 853/443 without root requires the `cap_net_bind_service`
capability on the binary, or just run it as root, or remap to high ports
in `config.toml` for local testing.

### Docker

A multi-stage `Dockerfile` is included; the runtime image runs as an
unprivileged user with `cap_net_bind_service` set on the binary via
`setcap`, so it doesn't need `--privileged` or `-u root` to bind 853/443.

Build it yourself:

```sh
docker build -t dns-rs .
```

Or pull the image CI publishes to GHCR on every push to `main` and on
version tags (`ghcr.io/legitcamper/dns-rs:latest`, `:<git-sha>`, or `:vX.Y.Z`).

Run it, mounting your config and TLS material read-only:

```sh
docker run -d \
  --name dns-rs \
  -p 853:853 \
  -p 443:443 \
  -v /path/to/config.toml:/etc/dns-rs/config.toml:ro \
  -v /path/to/fullchain.pem:/etc/dns-rs/fullchain.pem:ro \
  -v /path/to/privkey.pem:/etc/dns-rs/privkey.pem:ro \
  ghcr.io/legitcamper/dns-rs:latest
```

The entrypoint defaults to `--config /etc/dns-rs/config.toml`, so your
mounted config's `tls_cert`/`tls_key` paths should point at wherever you
mounted the cert/key inside the container (`/etc/dns-rs/fullchain.pem` and
`/etc/dns-rs/privkey.pem` above, to match).

There's no `docker-compose.yml` in the repo — the `docker run` invocation
above is the whole setup; wrap it in compose/systemd/whatever you already
use to manage containers if you want it supervised.

## Development

```sh
cargo test              # unit + integration tests, no network required
cargo clippy --all-targets
```

Tests use fake upstreams (no real network/TLS) to exercise fallback, race,
caching, and negative-caching behavior directly — see `dns::test_support`.
