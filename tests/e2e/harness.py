# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "dnspython>=2.6",
#   "httpx>=0.27",
# ]
# ///
"""End-to-end test harness for dns-rs.

Spins up real `dns-rs` server processes (release binary) against a
self-signed cert, drives them over real DoT/DoH sockets (no mocking of the
protocol layer), and exercises:

  * basic correctness: static hosts, blocklist, real upstream resolution,
    malformed queries, request-ID patching
  * cache hit/TTL behavior
  * upstream durability: fast-fail fallback, a hung upstream's effect on the
    shared deadline, sequential vs race under a blackholed upstream
  * cache saturation / LRU eviction under a deliberately tiny pool
  * sustained high-concurrency load, sampling RSS to look for leak-shaped
    growth
  * DoT connection cap + idle-timeout reaping of connections that complete a
    handshake and then never send a query (the pattern internet background
    scanners hitting port 853 actually produce)

Usage:
    uv run tests/e2e/harness.py [smoke|durability|cache|memory|dot-limits|all ...]

Requires `cargo build --release` to have been run first, and outbound
network access to a public DoH/DoT resolver (Cloudflare) for the tests that
need a real upstream.
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import dns.message
import dns.rcode
import dns.rdatatype
import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "target" / "release" / "dns-rs"
CERTS_DIR = Path(__file__).resolve().parent / "certs"
CERT_PATH = CERTS_DIR / "cert.pem"
KEY_PATH = CERTS_DIR / "key.pem"
RUN_DIR = Path(__file__).resolve().parent / ".run"

REAL_UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query"
REAL_UPSTREAM_DOT = "tls://1.1.1.1:853#cloudflare-dns.com"

UPSTREAM_TIMEOUT = 5.0  # must match dns-rs's own UPSTREAM_TIMEOUT constant

# Must match server/dot.rs's MAX_CONCURRENT_CONNECTIONS / IDLE_TIMEOUT.
DOT_MAX_CONNECTIONS = 512
DOT_IDLE_TIMEOUT = 120.0


# --------------------------------------------------------------------------
# Result tracking
# --------------------------------------------------------------------------


@dataclass
class Check:
    scenario: str
    name: str
    ok: bool
    detail: str = ""


RESULTS: list[Check] = []
_current_scenario = "unset"


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append(Check(_current_scenario, name, ok, detail))
    status = "PASS" if ok else "FAIL"
    line = f"  [{status}] {name}"
    if detail:
        line += f" \u2014 {detail}"
    print(line, flush=True)
    return ok


def section(name: str) -> None:
    global _current_scenario
    _current_scenario = name
    print(f"\n== {name} ==", flush=True)


# --------------------------------------------------------------------------
# Misc local infra
# --------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ensure_certs() -> None:
    if CERT_PATH.exists() and KEY_PATH.exists():
        return
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", str(KEY_PATH), "-out", str(CERT_PATH),
            "-days", "30", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )


class LocalHttpTextServer:
    """Minimal local HTTP server serving one fixed body on every path -
    used as a blocklist source so that scenario doesn't depend on any
    external network resource."""

    def __init__(self, body: bytes):
        self._body = body
        handler = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(handler._body)))
                self.end_headers()
                self.wfile.write(handler._body)

            def log_message(self, *args):  # silence
                pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self, path: str = "/list.txt") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


async def start_blackhole_server() -> tuple[asyncio.base_events.Server, int]:
    """A TCP server that accepts connections and then never speaks again -
    simulates an upstream that hangs instead of failing fast."""

    async def handle(reader, writer):
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


# --------------------------------------------------------------------------
# dns-rs server process management
# --------------------------------------------------------------------------


def render_config(
    *,
    dot_port: int,
    doh_port: int,
    upstream_urls: list[str],
    strategy: str = "sequential",
    cache_max_bytes: int = 64 * 1024 * 1024,
    cache_enabled: bool = True,
    blocklist_urls: list[str] | None = None,
    blocklist_domains: list[str] | None = None,
    whitelist: list[str] | None = None,
    whitelist_urls: list[str] | None = None,
    static_hosts: dict[str, str] | None = None,
    block_mode: str = "nxdomain",
) -> str:
    def toml_list(items: list[str]) -> str:
        return "[" + ", ".join(json.dumps(i) for i in items) + "]"

    static_hosts_lines = "\n".join(f'{json.dumps(k)} = {json.dumps(v)}' for k, v in (static_hosts or {}).items())

    return f'''
[server]
bind_address = "127.0.0.1"
dot_port = {dot_port}
doh_port = {doh_port}
tls_cert = {json.dumps(str(CERT_PATH))}
tls_key = {json.dumps(str(KEY_PATH))}
default_ttl = 60

[blocking]
mode = {json.dumps(block_mode)}
sinkhole_ip = "0.0.0.0"

[blocklists]
refresh_interval_secs = 43200
urls = {toml_list(blocklist_urls or [])}
domains = {toml_list(blocklist_domains or [])}

[whitelist]
refresh_interval_secs = 43200
urls = {toml_list(whitelist_urls or [])}
domains = {toml_list(whitelist or [])}

[upstream]
strategy = {json.dumps(strategy)}
urls = {toml_list(upstream_urls)}

[static_hosts]
{static_hosts_lines}

[cache]
enabled = {"true" if cache_enabled else "false"}
max_size_bytes = {cache_max_bytes}
'''


class DnsRsServer:
    def __init__(self, name: str, config_text: str, rust_log: str = "dns_rs=debug"):
        self.name = name
        self.config_text = config_text
        self.rust_log = rust_log
        self.proc: subprocess.Popen | None = None
        self.logs: list[str] = []
        self._log_thread: threading.Thread | None = None

    def __enter__(self) -> "DnsRsServer":
        run_dir = RUN_DIR / self.name
        run_dir.mkdir(parents=True, exist_ok=True)
        config_path = run_dir / "config.toml"
        config_path.write_text(self.config_text)

        env = os.environ.copy()
        env["RUST_LOG"] = self.rust_log
        self.proc = subprocess.Popen(
            [str(BINARY), "--config", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env,
        )
        self._log_thread = threading.Thread(target=self._drain_logs, daemon=True)
        self._log_thread.start()
        self._wait_ready(timeout=15)
        return self

    def _drain_logs(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            self.logs.append(line.rstrip("\n"))

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            for line in self.logs:
                if "DoT listener ready" in line:
                    seen.add("dot")
                if "DoH listener ready" in line:
                    seen.add("doh")
            if {"dot", "doh"} <= seen:
                return
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name}: server exited early (code {self.proc.returncode}):\n" + "\n".join(self.logs))
            time.sleep(0.05)
        raise RuntimeError(f"{self.name}: server did not become ready within {timeout}s:\n" + "\n".join(self.logs))

    def __exit__(self, *exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self._log_thread:
            self._log_thread.join(timeout=2)

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def rss_kb(self) -> int | None:
        if not self.proc:
            return None
        try:
            with open(f"/proc/{self.proc.pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except (FileNotFoundError, ProcessLookupError):
            return None
        return None

    def log_count(self, substr: str) -> int:
        return sum(1 for l in self.logs if substr in l)

    async def wait_for_log_count(self, substr: str, minimum: int = 1, timeout: float = 2.0) -> int:
        """Log lines land in `self.logs` slightly after the corresponding
        socket response is received (separate process, separate thread), so
        checks against log content need to tolerate that small race."""
        deadline = time.monotonic() + timeout
        count = self.log_count(substr)
        while count < minimum and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            count = self.log_count(substr)
        return count


# --------------------------------------------------------------------------
# DNS query helpers (real DoT/DoH sockets, no shortcuts)
# --------------------------------------------------------------------------


async def dot_query(port: int, query: dns.message.Message, timeout: float = 8.0) -> dns.message.Message:
    ctx = ssl.create_default_context(cafile=str(CERT_PATH))
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="localhost"), timeout=timeout
    )
    try:
        wire = query.to_wire()
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
        length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = int.from_bytes(length_bytes, "big")
        resp_wire = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        return dns.message.from_wire(resp_wire)
    finally:
        writer.close()


async def dot_query_raw(port: int, raw: bytes, timeout: float = 8.0) -> bytes:
    """Sends a raw (possibly malformed) length-prefixed payload and returns the raw response body."""
    ctx = ssl.create_default_context(cafile=str(CERT_PATH))
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="localhost"), timeout=timeout
    )
    try:
        writer.write(len(raw).to_bytes(2, "big") + raw)
        await writer.drain()
        length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = int.from_bytes(length_bytes, "big")
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    finally:
        writer.close()


async def doh_query(
    port: int,
    query: dns.message.Message,
    client: httpx.AsyncClient,
    timeout: float = 8.0,
    path: str = "/dns-query",
) -> dns.message.Message:
    wire = query.to_wire()
    resp = await client.post(
        f"https://localhost:{port}{path}",
        content=wire,
        headers={"content-type": "application/dns-message", "accept": "application/dns-message"},
        timeout=timeout,
    )
    resp.raise_for_status()
    return dns.message.from_wire(resp.content)


def make_query(name: str, rdtype: str = "A") -> dns.message.Message:
    return dns.message.make_query(name, rdtype, want_dnssec=False)


# --------------------------------------------------------------------------
# Scenario: basic correctness (smoke)
# --------------------------------------------------------------------------


async def scenario_smoke() -> bool:
    section("smoke: basic correctness")
    blocklist_server = LocalHttpTextServer(b"0.0.0.0 blocked.test.invalid\n")
    dot_port, doh_port = free_port(), free_port()
    config = render_config(
        dot_port=dot_port,
        doh_port=doh_port,
        upstream_urls=[REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT],
        blocklist_urls=[blocklist_server.url()],
        static_hosts={"nas.home": "192.168.1.10"},
    )
    ok = True
    try:
        with DnsRsServer("smoke", config) as server:
            # Static host, no upstream touched.
            q = make_query("nas.home", "A")
            resp = await dot_query(dot_port, q)
            ok &= check("static host resolves via DoT", resp.rcode() == dns.rcode.NOERROR and str(resp.answer[0][0]) == "192.168.1.10")
            ok &= check("static host response echoes request ID", resp.id == q.id)

            # Blocklist (DoH transport this time).
            async with httpx.AsyncClient(verify=str(CERT_PATH)) as client:
                for path in ("/", "/electric-boogoloo", "/dns-query"):
                    q = make_query("nas.home", "A")
                    resp = await doh_query(doh_port, q, client, path=path)
                    ok &= check(
                        f"static host resolves via DoH at {path}",
                        resp.rcode() == dns.rcode.NOERROR and str(resp.answer[0][0]) == "192.168.1.10",
                    )

                q = make_query("blocked.test.invalid", "A")
                resp = await doh_query(doh_port, q, client)
                ok &= check("blocklisted domain returns NXDOMAIN via DoH", resp.rcode() == dns.rcode.NXDOMAIN)

                # Real upstream resolution via DoH.
                q = make_query("example.com", "A")
                resp = await doh_query(doh_port, q, client)
                ok &= check(
                    "real upstream A record resolves via DoH",
                    resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0,
                    detail=f"rcode={dns.rcode.to_text(resp.rcode())} answers={len(resp.answer)}",
                )

            # Real upstream resolution via DoT.
            q = make_query("example.com", "A")
            resp = await dot_query(dot_port, q)
            ok &= check(
                "real upstream A record resolves via DoT",
                resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0,
            )

            # Malformed query must not crash the server and must return FORMERR.
            raw_resp = await dot_query_raw(dot_port, b"\x99\x01\x02not-a-real-dns-message")
            decoded = dns.message.from_wire(raw_resp)
            ok &= check("malformed query returns FORMERR, not a crash", decoded.rcode() == dns.rcode.FORMERR)
            ok &= check("server still alive after malformed query", server.is_alive())

            # Multiple distinct queries pipelined on one DoT connection.
            # Queries are now processed concurrently (see below), so
            # responses may arrive in a different order than requests were
            # sent - match by ID, not by position, same as a real client
            # (e.g. dnspython/dig) would.
            ctx = ssl.create_default_context(cafile=str(CERT_PATH))
            reader, writer = await asyncio.open_connection("127.0.0.1", dot_port, ssl=ctx, server_hostname="localhost")
            queries = [make_query(f"pipeline-{i}.nas.home" if i == 0 else "nas.home", "A") for i in range(3)]
            for q in queries:
                wire = q.to_wire()
                writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            responses = []
            for _ in queries:
                length = int.from_bytes(await reader.readexactly(2), "big")
                responses.append(dns.message.from_wire(await reader.readexactly(length)))
            writer.close()
            responses_by_id = {r.id: r for r in responses}
            ok &= check(
                "pipelined DoT queries each get a response matching their own ID",
                {q.id for q in queries} == set(responses_by_id) and all(responses_by_id[q.id].id == q.id for q in queries),
            )
    finally:
        blocklist_server.stop()

    # Whitelist URLs (not just inline whitelist domains) must override the
    # blocklist, on equal footing with a blocklist URL. Sinkhole mode gives
    # a blocked domain a distinct NOERROR+sinkhole-IP answer instead of
    # NXDOMAIN, so "blocked" and "whitelisted-and-forwarded-to-a-real-
    # upstream-that-says-NXDOMAIN-because-.invalid-doesn't-exist" are
    # actually distinguishable outcomes.
    block_server = LocalHttpTextServer(b"0.0.0.0 blocked-only.test.invalid\n0.0.0.0 blocked-and-allowed.test.invalid\n")
    allow_server = LocalHttpTextServer(b"blocked-and-allowed.test.invalid\n")
    try:
        wl_dot_port, wl_doh_port = free_port(), free_port()
        wl_config = render_config(
            dot_port=wl_dot_port,
            doh_port=wl_doh_port,
            upstream_urls=[REAL_UPSTREAM_DOH],
            blocklist_urls=[block_server.url()],
            whitelist_urls=[allow_server.url()],
            block_mode="sinkhole",
        )
        with DnsRsServer("smoke-whitelist-url", wl_config):
            resp = await dot_query(wl_dot_port, make_query("blocked-only.test.invalid", "A"))
            ok &= check(
                "a domain in the blocklist only is sinkholed",
                resp.rcode() == dns.rcode.NOERROR and str(resp.answer[0][0]) == "0.0.0.0",
            )

            resp = await dot_query(wl_dot_port, make_query("blocked-and-allowed.test.invalid", "A"))
            ok &= check(
                "a whitelist URL (not just inline whitelist domains) overrides the blocklist",
                resp.rcode() == dns.rcode.NXDOMAIN,
                detail="expected the query to be forwarded upstream (real NXDOMAIN for a .invalid name), not sinkholed",
            )
    finally:
        block_server.stop()
        allow_server.stop()

    # Concurrency proof: a slow pipelined miss must not block a faster
    # pipelined query behind it. Upstream is a "blackhole" that never
    # responds, so the miss stalls for the full upstream timeout - if the
    # connection still processed queries one at a time (the old behavior),
    # the first byte back on the wire would necessarily be that slow
    # response. With per-query concurrency, the fast static-host answer
    # should come back first, in well under a second.
    blackhole_server, blackhole_port = await start_blackhole_server()
    try:
        conc_dot_port, conc_doh_port = free_port(), free_port()
        conc_config = render_config(
            dot_port=conc_dot_port, doh_port=conc_doh_port,
            upstream_urls=[f"tls://127.0.0.1:{blackhole_port}#dead"],
            static_hosts={"fast.home": "10.0.0.9"},
        )
        with DnsRsServer("dot-pipelining-concurrency", conc_config):
            ctx = ssl.create_default_context(cafile=str(CERT_PATH))
            reader, writer = await asyncio.open_connection("127.0.0.1", conc_dot_port, ssl=ctx, server_hostname="localhost")
            slow_query = make_query("slow-miss.invalid", "A")
            fast_query = make_query("fast.home", "A")
            for q in (slow_query, fast_query):
                wire = q.to_wire()
                writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()

            t0 = time.monotonic()
            first_length = int.from_bytes(await reader.readexactly(2), "big")
            first_resp = dns.message.from_wire(await reader.readexactly(first_length))
            first_elapsed = time.monotonic() - t0
            writer.close()

            ok &= check(
                "a slow pipelined miss doesn't block a faster query behind it",
                first_resp.id == fast_query.id and first_elapsed < 1.0,
                detail=f"first response back in {first_elapsed * 1000:.0f}ms and {'was' if first_resp.id == fast_query.id else 'was NOT'} the fast one "
                f"(the slow one stalls ~{UPSTREAM_TIMEOUT:.0f}s against the blackhole)",
            )
    finally:
        blackhole_server.close()

    return ok


# --------------------------------------------------------------------------
# Scenario: cache hit / TTL id-patch behavior
# --------------------------------------------------------------------------


async def scenario_cache_basic() -> bool:
    section("cache: hit timing + ID patch")
    dot_port, doh_port = free_port(), free_port()
    config = render_config(dot_port=dot_port, doh_port=doh_port, upstream_urls=[REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT])
    ok = True
    with DnsRsServer("cache-basic", config) as server:
        q1 = make_query("example.com", "A")
        t0 = time.monotonic()
        resp1 = await dot_query(dot_port, q1)
        miss_latency = time.monotonic() - t0
        ok &= check("first query (cache miss) succeeds", resp1.rcode() == dns.rcode.NOERROR)

        q2 = make_query("example.com", "A")
        t0 = time.monotonic()
        resp2 = await dot_query(dot_port, q2)
        hit_latency = time.monotonic() - t0
        ok &= check("second identical query (cache hit) succeeds", resp2.rcode() == dns.rcode.NOERROR)
        ok &= check("cache hit carries the new request's ID, not the old one", resp2.id == q2.id and resp2.id != q1.id)
        ok &= check(
            "cache hit is meaningfully faster than the original miss",
            hit_latency < max(miss_latency * 0.5, 0.02),
            detail=f"miss={miss_latency * 1000:.1f}ms hit={hit_latency * 1000:.1f}ms",
        )
        ok &= check("cache hit answer matches the original", str(resp1.answer[0]) == str(resp2.answer[0]))
        hits = await server.wait_for_log_count("cache hit", minimum=1)
        ok &= check(f"{hits} cache-hit log line(s) observed", hits >= 1)
    return ok


# --------------------------------------------------------------------------
# Scenario: upstream durability
# --------------------------------------------------------------------------


async def scenario_durability() -> bool:
    section("durability: upstream fallback / shared deadline")
    ok = True

    refused_port = free_port()  # nothing listens here -> instant connection refused
    blackhole_server, blackhole_port = await start_blackhole_server()
    try:
        # A: one fast-failing dead upstream ahead of a real one -> should
        # succeed quickly (fast failure barely dents the shared deadline).
        dot_port, doh_port = free_port(), free_port()
        config = render_config(
            dot_port=dot_port, doh_port=doh_port,
            upstream_urls=[f"tls://127.0.0.1:{refused_port}#dead", REAL_UPSTREAM_DOH],
        )
        with DnsRsServer("durability-fast-fail", config) as server:
            t0 = time.monotonic()
            resp = await dot_query(dot_port, make_query("example.com", "A"), timeout=UPSTREAM_TIMEOUT + 2)
            elapsed = time.monotonic() - t0
            ok &= check(
                "fast-failing upstream falls back to a working one and succeeds",
                resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0,
            )
            ok &= check(
                "fallback after a fast failure stays well under the full upstream timeout",
                elapsed < UPSTREAM_TIMEOUT * 0.9,
                detail=f"elapsed={elapsed:.2f}s (budget={UPSTREAM_TIMEOUT}s)",
            )

        # D: two fast-failing dead upstreams ahead of a real one -> still succeeds quickly.
        dot_port, doh_port = free_port(), free_port()
        config = render_config(
            dot_port=dot_port, doh_port=doh_port,
            upstream_urls=[f"tls://127.0.0.1:{refused_port}#dead", f"tls://127.0.0.1:{free_port()}#dead2", REAL_UPSTREAM_DOH],
        )
        with DnsRsServer("durability-multi-fast-fail", config) as server:
            t0 = time.monotonic()
            resp = await dot_query(dot_port, make_query("example.com", "A"), timeout=UPSTREAM_TIMEOUT + 2)
            elapsed = time.monotonic() - t0
            ok &= check(
                "two fast-failing dead upstreams still fall through to a working third",
                resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0,
            )
            ok &= check(
                "multiple fast failures don't each cost their own timeout",
                elapsed < UPSTREAM_TIMEOUT * 0.9,
                detail=f"elapsed={elapsed:.2f}s (budget={UPSTREAM_TIMEOUT}s)",
            )

        # B: a HUNG upstream ahead of a real one, sequential strategy. This
        # is the key regression check for the shared-deadline diff: total
        # latency must stay bounded to ~UPSTREAM_TIMEOUT (not blow past it),
        # even though the practical consequence is the real upstream never
        # gets tried (the hang consumes the whole shared budget). That's a
        # real characteristic worth knowing, not a bug in the bound itself.
        dot_port, doh_port = free_port(), free_port()
        config = render_config(
            dot_port=dot_port, doh_port=doh_port, strategy="sequential",
            upstream_urls=[f"tls://127.0.0.1:{blackhole_port}#dead", REAL_UPSTREAM_DOH],
        )
        with DnsRsServer("durability-hang-sequential", config) as server:
            t0 = time.monotonic()
            resp = await dot_query(dot_port, make_query("example.com", "A"), timeout=UPSTREAM_TIMEOUT + 3)
            elapsed = time.monotonic() - t0
            ok &= check(
                "a hung first upstream still bounds total sequential latency to ~1 timeout, not more",
                UPSTREAM_TIMEOUT * 0.8 < elapsed < UPSTREAM_TIMEOUT * 1.3,
                detail=f"elapsed={elapsed:.2f}s (budget={UPSTREAM_TIMEOUT}s)",
            )
            check(
                "(informational) a hung first upstream starves the working fallback within one query",
                resp.rcode() == dns.rcode.SERVFAIL,
                detail="expected: the shared deadline is spent entirely on the hung entry, so the real upstream is never tried; put reliable upstreams first",
            )

        # E: same hung-upstream setup, but RACE strategy -> should succeed
        # quickly since race queries every upstream concurrently instead of
        # spending the deadline sequentially.
        dot_port, doh_port = free_port(), free_port()
        config = render_config(
            dot_port=dot_port, doh_port=doh_port, strategy="race",
            upstream_urls=[f"tls://127.0.0.1:{blackhole_port}#dead", REAL_UPSTREAM_DOH],
        )
        with DnsRsServer("durability-hang-race", config) as server:
            t0 = time.monotonic()
            resp = await dot_query(dot_port, make_query("example.com", "A"), timeout=UPSTREAM_TIMEOUT + 3)
            elapsed = time.monotonic() - t0
            ok &= check(
                "race strategy shrugs off a hung upstream and answers quickly",
                resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0 and elapsed < UPSTREAM_TIMEOUT * 0.5,
                detail=f"elapsed={elapsed:.2f}s",
            )

        # C: every upstream dead (mix of hang + fast-fail) -> SERVFAIL, and
        # crucially the client is never left hanging past ~1 timeout.
        dot_port, doh_port = free_port(), free_port()
        config = render_config(
            dot_port=dot_port, doh_port=doh_port, strategy="sequential",
            upstream_urls=[f"tls://127.0.0.1:{refused_port}#dead", f"tls://127.0.0.1:{blackhole_port}#dead2"],
        )
        with DnsRsServer("durability-all-dead", config) as server:
            t0 = time.monotonic()
            resp = await dot_query(dot_port, make_query("example.com", "A"), timeout=UPSTREAM_TIMEOUT + 3)
            elapsed = time.monotonic() - t0
            ok &= check("all upstreams dead returns SERVFAIL, not silence", resp.rcode() == dns.rcode.SERVFAIL)
            ok &= check(
                "all-dead failure is still bounded to ~1 timeout, not N timeouts",
                elapsed < UPSTREAM_TIMEOUT * 1.3,
                detail=f"elapsed={elapsed:.2f}s (old N\u00d7timeout behavior would be >={UPSTREAM_TIMEOUT * 2:.0f}s here)",
            )
    finally:
        # Not `await wait_closed()`: the blackhole handler tasks are asleep
        # forever by design and never observe the client disconnecting, so
        # on modern asyncio (which waits for accepted connections too) that
        # would hang forever. `close()` alone stops accepting new
        # connections; the leftover sleeping tasks are abandoned when the
        # process exits shortly after.
        blackhole_server.close()
    return ok


# --------------------------------------------------------------------------
# Scenario: cache saturation / eviction under a tiny pool
# --------------------------------------------------------------------------


async def scenario_cache_saturation() -> bool:
    section("cache: saturation & LRU eviction under a tiny pool")
    dot_port, doh_port = free_port(), free_port()
    # Small enough that only a couple dozen small NXDOMAIN responses fit -
    # eviction must kick in constantly.
    config = render_config(dot_port=dot_port, doh_port=doh_port, upstream_urls=[REAL_UPSTREAM_DOH], cache_max_bytes=3072)
    ok = True
    with DnsRsServer("cache-saturation", config) as server:
        names = [f"churn-{i}-{os.urandom(3).hex()}.invalid" for i in range(150)]
        async with httpx.AsyncClient(verify=str(CERT_PATH)) as client:
            sem = asyncio.Semaphore(10)

            async def one(name: str):
                async with sem:
                    return await doh_query(doh_port, make_query(name, "A"), client)

            responses = await asyncio.gather(*(one(n) for n in names), return_exceptions=True)

        exceptions = [r for r in responses if isinstance(r, Exception)]
        ok &= check(f"all {len(names)} unique queries against a tiny cache completed without error", len(exceptions) == 0, detail=str(exceptions[:3]))
        ok &= check("server survives sustained cache pressure", server.is_alive())

        evictions = await server.wait_for_log_count("evicted a cache entry to make room", minimum=1)
        ok &= check(f"LRU eviction actually triggered ({evictions} evictions logged)", evictions > 0)

        # Re-query one of the earliest names: with such a tiny pool it must
        # have been evicted long ago, so this must be a fresh miss again
        # (not silently wrong/stale), and must still answer correctly.
        async with httpx.AsyncClient(verify=str(CERT_PATH)) as client:
            resp = await doh_query(doh_port, make_query(names[0], "A"), client)
        ok &= check("re-querying a long-evicted name still resolves correctly", resp.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR))
    return ok


# --------------------------------------------------------------------------
# Scenario: sustained high-concurrency load / memory behavior
# --------------------------------------------------------------------------

WARM_DOMAINS = [
    "example.com", "example.net", "example.org", "cloudflare.com", "wikipedia.org",
    "mozilla.org", "python.org", "rust-lang.org", "iana.org", "one.one.one.one",
]


async def scenario_memory_churn(
    duration_s: float = float(os.environ.get("E2E_MEMORY_DURATION_S", 15.0)),
    concurrency: int = int(os.environ.get("E2E_MEMORY_CONCURRENCY", 64)),
) -> bool:
    section("memory: sustained high-concurrency churn")
    dot_port, doh_port = free_port(), free_port()
    config = render_config(dot_port=dot_port, doh_port=doh_port, upstream_urls=[REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT])
    ok = True
    with DnsRsServer("memory-churn", config, rust_log="dns_rs=info") as server:
        # Warm the cache so the bulk of the storm below is cache hits -
        # this is about churning the server's own per-request allocations
        # (wire encode/copy, TLS buffers, tokio tasks) under sustained QPS,
        # not about hammering the public upstream.
        async with httpx.AsyncClient(verify=str(CERT_PATH)) as client:
            for name in WARM_DOMAINS:
                await doh_query(doh_port, make_query(name, "A"), client)

        rss_samples: list[tuple[float, int]] = []
        stop = threading.Event()

        def sample_rss():
            start = time.monotonic()
            while not stop.is_set():
                rss = server.rss_kb()
                if rss is not None:
                    rss_samples.append((time.monotonic() - start, rss))
                time.sleep(0.4)

        sampler = threading.Thread(target=sample_rss, daemon=True)
        sampler.start()

        stats = {"requests": 0, "errors": 0}
        deadline = time.monotonic() + duration_s

        async def dot_worker(worker_id: int):
            while time.monotonic() < deadline:
                try:
                    if worker_id % 5 == 0:
                        name = f"churn-{os.urandom(4).hex()}.invalid"
                    else:
                        name = WARM_DOMAINS[worker_id % len(WARM_DOMAINS)]
                    await dot_query(dot_port, make_query(name, "A"), timeout=6.0)
                    stats["requests"] += 1
                except Exception:
                    stats["errors"] += 1
                    stats["requests"] += 1

        async def doh_worker(client: httpx.AsyncClient, worker_id: int):
            while time.monotonic() < deadline:
                try:
                    if worker_id % 5 == 0:
                        name = f"churn-{os.urandom(4).hex()}.invalid"
                    else:
                        name = WARM_DOMAINS[worker_id % len(WARM_DOMAINS)]
                    await doh_query(doh_port, make_query(name, "A"), client, timeout=6.0)
                    stats["requests"] += 1
                except Exception:
                    stats["errors"] += 1
                    stats["requests"] += 1

        dot_workers = concurrency // 3
        doh_workers = concurrency - dot_workers
        async with httpx.AsyncClient(verify=str(CERT_PATH), limits=httpx.Limits(max_connections=doh_workers + 5)) as client:
            tasks = [asyncio.create_task(dot_worker(i)) for i in range(dot_workers)]
            tasks += [asyncio.create_task(doh_worker(client, i)) for i in range(doh_workers)]
            await asyncio.gather(*tasks)

        stop.set()
        sampler.join(timeout=2)

        error_rate = stats["errors"] / max(stats["requests"], 1)
        ok &= check(
            f"sustained load completed ({stats['requests']} requests over {duration_s:.0f}s, {concurrency} workers)",
            stats["requests"] > 0,
        )
        ok &= check(f"error rate under load stayed low ({error_rate:.2%})", error_rate < 0.02)
        ok &= check("server survived the load burst", server.is_alive())

        if len(rss_samples) >= 4:
            first_third = rss_samples[: len(rss_samples) // 3]
            last_third = rss_samples[-len(rss_samples) // 3 :]
            avg_first = sum(v for _, v in first_third) / len(first_third)
            avg_last = sum(v for _, v in last_third) / len(last_third)
            peak = max(v for _, v in rss_samples)
            drift_mb = (avg_last - avg_first) / 1024
            print(f"  RSS: start~{rss_samples[0][1] / 1024:.1f}MB peak={peak / 1024:.1f}MB end~{rss_samples[-1][1] / 1024:.1f}MB "
                  f"(first-third avg {avg_first / 1024:.1f}MB -> last-third avg {avg_last / 1024:.1f}MB)")
            ok &= check(
                "RSS in the final third of the run isn't still climbing sharply (no leak-shaped growth in this burst)",
                drift_mb < 25,
                detail=f"drift={drift_mb:.1f}MB over the run's last third (informational only for a single short burst)",
            )
        else:
            check("collected enough RSS samples to judge memory trend", False, detail=f"only {len(rss_samples)} samples")
    return ok


async def scenario_dot_connection_limits() -> bool:
    """Exercises `server/dot.rs`'s `MAX_CONCURRENT_CONNECTIONS`/`IDLE_TIMEOUT`:
    a connection that completes a TCP+TLS handshake and then never sends a
    real query, the pattern internet background scanners hitting the DoT
    port actually produce. Unlike `memory_churn`'s DoT worker, which always
    sends a complete query and closes promptly, this scenario deliberately
    never sends one.

    Slow (~2.5 min) by design: it waits out the real `IDLE_TIMEOUT` instead
    of mocking it, same philosophy as `durability`'s real `UPSTREAM_TIMEOUT`
    waits.
    """
    section("dot: connection cap and idle-timeout reaping")
    dot_port, doh_port = free_port(), free_port()
    config = render_config(dot_port=dot_port, doh_port=doh_port, upstream_urls=[REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT])
    ok = True
    ctx = ssl.create_default_context(cafile=str(CERT_PATH))

    async def try_connect():
        try:
            return await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", dot_port, ssl=ctx, server_hostname="localhost"), timeout=10.0
            )
        except Exception:
            return None

    async def is_closed(reader: asyncio.StreamReader) -> bool:
        try:
            return await asyncio.wait_for(reader.read(1), timeout=0.2) == b""
        except asyncio.TimeoutError:
            return False
        except (ConnectionResetError, asyncio.IncompleteReadError):
            return True

    with DnsRsServer("dot-connection-limits", config) as server:
        baseline = await dot_query(dot_port, make_query("example.com", "A"))
        ok &= check("baseline DoT query succeeds before saturation", baseline.rcode() == dns.rcode.NOERROR)

        # --- Cap enforcement: open well past DOT_MAX_CONNECTIONS at once,
        # completing the TLS handshake but sending nothing. Connections
        # beyond the cap get dropped by the server before/without completing
        # a handshake, which asyncio surfaces as an exception from
        # open_connection rather than a usable (reader, writer) pair.
        attempt_count = DOT_MAX_CONNECTIONS + 80
        results = await asyncio.gather(*(try_connect() for _ in range(attempt_count)))
        established = [pair for pair in results if pair is not None]

        ok &= check(
            f"connection cap rejected the excess (established {len(established)}/{attempt_count}, cap {DOT_MAX_CONNECTIONS})",
            len(established) <= DOT_MAX_CONNECTIONS,
            detail=f"established={len(established)}",
        )
        ok &= check(
            "cap wasn't so aggressive it rejected everything under it",
            len(established) > DOT_MAX_CONNECTIONS * 0.8,
            detail=f"established={len(established)}",
        )
        rejected_logged = await server.wait_for_log_count("DoT connection limit reached", minimum=1, timeout=5.0)
        ok &= check("server logged rejections for the over-cap connections", rejected_logged > 0)

        # Free those slots by disconnecting client-side (detected promptly,
        # same as any real disconnect) rather than waiting out IDLE_TIMEOUT
        # here - that's what the next part actually tests.
        for _reader, writer in established:
            writer.close()
        await asyncio.sleep(0.5)

        recovered = await dot_query(dot_port, make_query("example.com", "A"))
        ok &= check("a slot frees up once the saturating connections disconnect", recovered.rcode() == dns.rcode.NOERROR)

        # --- Idle-timeout reaping: a handful of connections that complete
        # the TLS handshake and then go silent should get closed by the
        # server on its own, without the client ever sending anything.
        stalled_count = 5
        stalled = await asyncio.gather(*(try_connect() for _ in range(stalled_count)))
        stalled = [pair for pair in stalled if pair is not None]
        ok &= check(f"{stalled_count} stalled connections established", len(stalled) == stalled_count)

        mid = await dot_query(dot_port, make_query("example.com", "A"))
        ok &= check("server stays responsive while connections are idling", mid.rcode() == dns.rcode.NOERROR)

        closed = 0
        deadline = time.monotonic() + DOT_IDLE_TIMEOUT + 15.0
        while time.monotonic() < deadline:
            statuses = await asyncio.gather(*(is_closed(reader) for reader, _writer in stalled))
            closed = sum(statuses)
            if closed == len(stalled):
                break
            await asyncio.sleep(2.0)

        ok &= check(
            f"all {len(stalled)} idle connections were closed by the server within IDLE_TIMEOUT+margin",
            closed == len(stalled),
            detail=f"closed={closed}/{len(stalled)}",
        )
        idle_closed_logged = server.log_count("closing idle DoT connection")
        ok &= check(
            "server logged the idle closures", idle_closed_logged >= len(stalled), detail=f"count={idle_closed_logged}"
        )

        for _reader, writer in stalled:
            writer.close()

        ok &= check("server survived the whole scenario", server.is_alive())
        final = await dot_query(dot_port, make_query("example.com", "A"))
        ok &= check("server still answers real queries after the reaping cycle", final.rcode() == dns.rcode.NOERROR)

    return ok


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

SCENARIOS = {
    "smoke": scenario_smoke,
    "cache": scenario_cache_basic,
    "cache-saturation": scenario_cache_saturation,
    "durability": scenario_durability,
    "memory": scenario_memory_churn,
    "dot-limits": scenario_dot_connection_limits,
}


async def run(selected: list[str]) -> int:
    if not BINARY.exists():
        print(f"error: {BINARY} not found - run `cargo build --release` first", file=sys.stderr)
        return 2
    if shutil.which("openssl") is None:
        print("error: openssl not found on PATH (needed to generate the test cert)", file=sys.stderr)
        return 2
    ensure_certs()
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    overall_ok = True
    for name in selected:
        fn = SCENARIOS[name]
        try:
            ok = await fn()
        except Exception as exc:  # noqa: BLE001
            check(f"scenario '{name}' crashed", False, detail=repr(exc))
            ok = False
        overall_ok &= ok

    print("\n" + "=" * 70)
    passed = sum(1 for c in RESULTS if c.ok)
    failed = [c for c in RESULTS if not c.ok]
    print(f"RESULT: {passed}/{len(RESULTS)} checks passed")
    if failed:
        print("\nFailed checks:")
        for c in failed:
            print(f"  [{c.scenario}] {c.name}" + (f" \u2014 {c.detail}" if c.detail else ""))
    return 0 if overall_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenarios", nargs="*", default=["all"], choices=[*SCENARIOS, "all"], help="which scenarios to run")
    args = parser.parse_args()
    selected = list(SCENARIOS) if "all" in args.scenarios else args.scenarios
    code = asyncio.run(run(selected))
    sys.exit(code)


if __name__ == "__main__":
    main()
