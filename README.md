# dns-rs

Self-hosted, ad-blocking DNS resolver that only speaks **encrypted** DNS —
DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH).

Point your router or devices at it instead of your ISP's resolver. Ads and
trackers get dropped before they resolve, and the queries that do go upstream
are encrypted end to end.

Written in Rust: a single stripped binary, no runtime, no GC, no interpreter.
It idles at a few MB of RAM and answers cache hits without allocating, so it's
happy on a Raspberry Pi, an old NUC, or a free serverless tier.

## What you get

- **DoT on 853 and DoH on 443**, both TLS-terminated by the resolver itself.
  Nothing listens on plaintext port 53.
- **Blocklists** fetched over HTTPS on a schedule you set. Hosts-file format,
  plain domain-per-line, and Adblock Plus network rules (`||domain^`) all work
  — point it at StevenBlack/hosts and you're done.
- **Whitelist** of exact domains that override every blocklist, re-applied on
  every refresh so a background update can't re-block something you carved out.
- **Static hosts** — `nas.home = 192.168.1.10` style overrides, answered
  locally, never forwarded upstream.
- **Block mode**: NXDOMAIN, or sinkhole to an IP you pick (Pi-hole style).
- **Fast cache** with a byte budget instead of an entry count, so tiny NXDOMAIN
  answers and fat TXT records each use only what they need. Failures (NXDOMAIN
  / NODATA) get cached too, when upstream says how long that's safe.
- **Multiple upstreams**: try them in order, or race all of them and take the
  first answer. Duplicate in-flight queries collapse into one upstream request.
- **Hot config reload** — edit `config.toml` and it picks up the change without
  restarting or dropping connections.

## Quick start (Docker)

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

Start from `config.example.toml` — every option is commented. Shape of it:

```toml
[server]        # bind address, DoT/DoH ports, TLS cert/key paths
[blocking]      # nxdomain or sinkhole, and the sinkhole IP
[blocklists]    # URLs to fetch, refresh interval
[whitelist]     # domains blocklists may never block
[upstream]      # DoT/DoH upstream resolvers, sequential or race
[static_hosts]  # your own domain -> IP overrides
[cache]         # enabled + total byte budget
```

The image runs as an unprivileged user with `cap_net_bind_service` on the
binary, so binding 853/443 needs no `--privileged` and no `-u root`. Your
config's `tls_cert`/`tls_key` should point at the paths you mounted inside the
container. Tags: `:latest`, `:<git-sha>`, `:vX.Y.Z`.

You need a TLS certificate: self-signed is fine if you can trust it on your
clients, or use a DNS-validated ACME cert if the resolver has a public name.

## From source

```sh
cargo build --release
./target/release/dns-rs --config /path/to/config.toml
```

Binding 853/443 without root needs `cap_net_bind_service` on the binary, or
just use high ports in `config.toml`.

## Platform TLS (Fly, Cloud Run, Azure, etc.)

The server can expose plaintext internal listeners for platforms that terminate
TLS at the edge. `serverless` selects environment-variable configuration;
`certless` selects plaintext inbound transports; `dot` and `doh` independently
select protocols. Outbound queries remain encrypted.

The published serverless image enables all four features and listens on
`0.0.0.0:8853` for DNS-over-TCP and `0.0.0.0:${PORT:-8053}` for HTTP DoH:

```sh
docker run --rm -p 8853:8853 -p 8053:8053 \
  ghcr.io/legitcamper/dns-rs-serverless:latest
```

**Do not expose these listeners directly to an untrusted network.** They are
only safe behind a TLS-terminating proxy.

### Fly.io

`fly.toml` maps public DoH 443 and DoT 853 to those internal listeners, uses
Fly-managed certificates, and keeps one Machine running to avoid DNS cold
starts:

```sh
fly launch --no-deploy
fly certs add dns.example.com
fly deploy
```

Set your Fly app name and primary region during `fly launch`; the checked-in config
intentionally omits account-specific values. Clients use
`https://dns.example.com/dns-query` for DoH and `dns.example.com:853` for DoT.

<details>
<summary>Environment variables</summary>

| Variable | Default |
|---|---|
| `PORT` / `DNSRS_DOH_PORT` | `8053` (`PORT` wins) |
| `DNSRS_DOT_PORT` | `8853` |
| `DNSRS_BIND_ADDRESS` | `0.0.0.0` |
| `DNSRS_TLS_CERT`, `DNSRS_TLS_KEY` | required only without `certless` |
| `DNSRS_UPSTREAM_URLS` | `https://cloudflare-dns.com/dns-query` |
| `DNSRS_UPSTREAM_STRATEGY` | `hedged` (`sequential`, `hedged`, or `race`) |
| `DNSRS_BLOCKLIST_URLS`, `DNSRS_BLOCKLIST_DOMAINS` | empty comma-separated lists |
| `DNSRS_WHITELIST_URLS`, `DNSRS_WHITELIST_DOMAINS` | empty comma-separated lists |
| `DNSRS_BLOCKLIST_REFRESH_SECS`, `DNSRS_WHITELIST_REFRESH_SECS` | `43200` |
| `DNSRS_BLOCK_MODE`, `DNSRS_SINKHOLE_IP` | `nxdomain`, `0.0.0.0` |
| `DNSRS_STATIC_HOSTS` | empty; format `name=ip,name2=ip2` |
| `DNSRS_CACHE_ENABLED` | `true` |
| `DNSRS_CACHE_MAX_SIZE_BYTES` | ¼ of cgroup memory, clamped to 1–64 MiB; ceiling 1 GiB |
| `DNSRS_DEFAULT_TTL` | `300` |

Build the Fly profile:

```sh
docker build \
  --build-arg 'CARGO_ARGS=--no-default-features --features serverless,certless,dot,doh' \
  -t dns-rs-serverless .
```

A DoH-only platform profile (for example Azure) uses
`--no-default-features --features serverless,certless,doh`.

</details>

## Know before you deploy

- **No plaintext DNS on port 53.** Devices that only speak classic DNS need a
  client-side proxy (`stubby`, `dnscrypt-proxy`) in front of this.
- **No DNSSEC validation.**
- **No IPv6 in synthesized answers** — static hosts and sinkhole mode produce
  `A` records only. `AAAA` queries against those names get NOERROR/NODATA,
  which still blocks them, just without a v6 sinkhole address.
- **No ACLs or auth.** Anything that can reach the ports can query it. Firewall
  it like any other internal service.
- **Single instance, no clustering.** For redundancy, run two independent
  instances behind DNS-level failover, not two sharing state.
- This is a home-network / single-box resolver, not a BIND/Unbound/CoreDNS
  replacement at scale. It has not been fuzzed, load-tested, or security
  reviewed by anyone but its author.

## Development

```sh
cargo test              # unit + integration tests, no network required
cargo clippy --all-targets
```

Tests use fake upstreams (no real network/TLS) to exercise fallback, race,
caching, and negative-caching behavior — see `dns::test_support`.
