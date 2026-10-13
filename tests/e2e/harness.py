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
    uv run tests/e2e/harness.py [smoke|durability|cache|memory|dot-limits|perf-local|perf-live|all ...]

Local scenarios require `cargo build --release` (or `DNSRS_E2E_BINARY`) and
some require outbound access to a public DoH/DoT resolver. Performance modes
are opt-in; `all` preserves the existing correctness scenario set.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import http.server
import json
import os
import platform
import random
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import dns.message
import dns.rcode
import dns.rdatatype
import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("DNSRS_E2E_BINARY", REPO_ROOT / "target" / "release" / "dns-rs")).expanduser().resolve()
CERTS_DIR = Path(__file__).resolve().parent / "certs"
CERT_PATH = CERTS_DIR / "cert.pem"
KEY_PATH = CERTS_DIR / "key.pem"
RUN_DIR = Path(__file__).resolve().parent / ".run"

REAL_UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query"
REAL_UPSTREAM_DOT = "tls://1.1.1.1:853#cloudflare-dns.com"
LIVE_DOT_TARGETS = {
    "dns-rs-fly": (
        os.environ.get("E2E_PERF_FLY_HOST", "dns-rs-cold-hollow-7445.fly.dev"),
        853,
        os.environ.get("E2E_PERF_FLY_HOST", "dns-rs-cold-hollow-7445.fly.dev"),
    ),
    "cloudflare": (os.environ.get("E2E_PERF_CLOUDFLARE_IP", "1.1.1.1"), 853, "cloudflare-dns.com"),
}
PERF_REQUESTS = int(os.environ.get("E2E_PERF_REQUESTS", "50"))
PERF_WARMUP = int(os.environ.get("E2E_PERF_WARMUP", "10"))
PERF_LIVE_RATE = float(os.environ.get("E2E_PERF_LIVE_RATE", "1"))
PERF_SEED = int(os.environ.get("E2E_PERF_SEED", "20260413"))


@dataclass
class PerfOptions:
    binary_a: Path = BINARY
    binary_b: Path | None = None
    label_a: str = "baseline"
    label_b: str = "candidate"
    output: Path | None = None
    seed: int = PERF_SEED
    rounds: int = 8
    requests: int = PERF_REQUESTS
    warmup: int = PERF_WARMUP
    concurrency: int = 8
    timeout: float = 8.0
    live_rate: float = PERF_LIVE_RATE
    fly_host: str = os.environ.get("E2E_PERF_FLY_HOST", "dns-rs-cold-hollow-7445.fly.dev")
    fly_doh_url: str = ""
    cloudflare_dot_host: str = os.environ.get("E2E_PERF_CLOUDFLARE_IP", "1.1.1.1")
    cloudflare_doh_url: str = REAL_UPSTREAM_DOH
    sweep_seconds: float = 31.0


PERF_OPTIONS = PerfOptions()

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
        valid = subprocess.run(
            ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(CERT_PATH)],
            capture_output=True,
        ).returncode == 0
        if valid:
            return
        CERT_PATH.unlink()
        KEY_PATH.unlink()
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
    def __init__(
        self,
        name: str,
        config_text: str,
        rust_log: str = "dns_rs=debug",
        *,
        binary: Path | None = None,
        ports: tuple[int, int] | None = None,
    ):
        self.name = name
        self.config_text = config_text
        self.rust_log = rust_log
        self.binary = binary or BINARY
        self.ports = ports
        self.proc: subprocess.Popen | None = None
        self.logs: list[str] = []
        self._log_thread: threading.Thread | None = None
        self.returncode: int | None = None
        self.forced_kill = False

    def __enter__(self) -> "DnsRsServer":
        run_dir = RUN_DIR / self.name
        run_dir.mkdir(parents=True, exist_ok=True)
        config_path = run_dir / "config.toml"
        config_path.write_text(self.config_text)

        env = os.environ.copy()
        env["RUST_LOG"] = self.rust_log
        self.proc = subprocess.Popen(
            [str(self.binary), "--config", str(config_path)],
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
        ports = set(self.ports or ())
        if not ports:
            for line in self.config_text.splitlines():
                key, _, value = line.partition("=")
                if key.strip() in {"dot_port", "doh_port"}:
                    ports.add(int(value.strip()))
        ready: set[int] = set()
        while time.time() < deadline:
            for port in ports - ready:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.1)
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        ready.add(port)
            if ready == ports:
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
                self.forced_kill = True
                self.proc.kill()
                self.proc.wait()
        if self.proc:
            self.returncode = self.proc.returncode
        if self._log_thread:
            self._log_thread.join(timeout=2)

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def resource_snapshot(self) -> dict | None:
        if not self.proc:
            return None
        try:
            stat = Path(f"/proc/{self.proc.pid}/stat").read_text().split()
            status = {}
            for line in Path(f"/proc/{self.proc.pid}/status").read_text().splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    status[key] = value.strip()
            ticks = os.sysconf("SC_CLK_TCK")
            return {
                "user_cpu_s": int(stat[13]) / ticks,
                "system_cpu_s": int(stat[14]) / ticks,
                "rss_kb": int(status["VmRSS"].split()[0]) if "VmRSS" in status else None,
                "peak_rss_kb": int(status["VmHWM"].split()[0]) if "VmHWM" in status else None,
                "threads": int(status["Threads"]) if "Threads" in status else None,
                "voluntary_context_switches": int(status["voluntary_ctxt_switches"]) if "voluntary_ctxt_switches" in status else None,
                "involuntary_context_switches": int(status["nonvoluntary_ctxt_switches"]) if "nonvoluntary_ctxt_switches" in status else None,
            }
        except (FileNotFoundError, KeyError, ProcessLookupError, ValueError):
            return None

    def rss_kb(self) -> int | None:
        snapshot = self.resource_snapshot()
        return snapshot["rss_kb"] if snapshot else None

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


class PersistentDotClient:
    """Multiplexed DoT client that keeps one TLS connection open."""

    def __init__(self, host: str, port: int, server_hostname: str, ssl_context: ssl.SSLContext, timeout: float = 8.0):
        self.host = host
        self.port = port
        self.server_hostname = server_hostname
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._reader_task: asyncio.Task | None = None
        self._write_lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self.connection_ms: float | None = None

    async def __aenter__(self) -> "PersistentDotClient":
        started = time.perf_counter_ns()
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=self.ssl_context,
                server_hostname=self.server_hostname,
            ),
            timeout=self.timeout,
        )
        self.connection_ms = (time.perf_counter_ns() - started) / 1_000_000
        self._reader_task = asyncio.create_task(self._read_responses())
        return self

    async def __aexit__(self, *exc) -> None:
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
        if self._reader_task:
            self._reader_task.cancel()
            await asyncio.gather(self._reader_task, return_exceptions=True)

    def _allocate_id(self) -> int:
        for _ in range(65_536):
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id not in self._pending:
                return self._next_id
        raise RuntimeError("all DNS request IDs are in flight")

    async def _read_responses(self) -> None:
        assert self.reader is not None
        try:
            while True:
                length_bytes = await self.reader.readexactly(2)
                length = int.from_bytes(length_bytes, "big")
                response = dns.message.from_wire(await self.reader.readexactly(length))
                future = self._pending.pop(response.id, None)
                if future is not None and not future.done():
                    future.set_result(response)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(exc)
            self._pending.clear()

    async def query(self, query: dns.message.Message) -> dns.message.Message:
        assert self.writer is not None
        query.id = self._allocate_id()
        future = asyncio.get_running_loop().create_future()
        self._pending[query.id] = future
        wire = query.to_wire()
        try:
            async with self._write_lock:
                self.writer.write(len(wire).to_bytes(2, "big") + wire)
                await asyncio.wait_for(self.writer.drain(), timeout=self.timeout)
            return await asyncio.wait_for(future, timeout=self.timeout)
        except BaseException:
            self._pending.pop(query.id, None)
            raise


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
# Scenarios: repeatable performance evidence
# --------------------------------------------------------------------------


def percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    index = (len(sorted_values) - 1) * p
    lower = int(index)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (index - lower)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_text(*command: str) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        return (result.stdout or result.stderr).strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def binary_metadata(label: str, path: Path) -> dict:
    return {
        "label": label,
        "path": str(path),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def metric_delta(before: dict, after: dict, key: str) -> int | float | None:
    start, end = before.get(key), after.get(key)
    return end - start if start is not None and end is not None else None


def resource_delta(before: dict | None, after: dict | None, successes: int) -> dict | None:
    if before is None or after is None:
        return None
    user = metric_delta(before, after, "user_cpu_s")
    system = metric_delta(before, after, "system_cpu_s")
    total = user + system if user is not None and system is not None else None
    return {
        "user_cpu_s": user,
        "system_cpu_s": system,
        "total_cpu_s": total,
        "cpu_us_per_success": total * 1_000_000 / successes if total is not None and successes else None,
        "rss_start_kb": before.get("rss_kb"),
        "rss_end_kb": after.get("rss_kb"),
        "peak_rss_kb": after.get("peak_rss_kb"),
        "threads_end": after.get("threads"),
        "voluntary_context_switches": metric_delta(before, after, "voluntary_context_switches"),
        "involuntary_context_switches": metric_delta(before, after, "involuntary_context_switches"),
    }


def validate_dns_response(query: dns.message.Message, response: dns.message.Message, expected_rcode: int, expected_ip: str | None) -> None:
    if response.id != query.id:
        raise ValueError(f"response ID mismatch: expected {query.id}, got {response.id}")
    if len(response.question) != 1 or len(query.question) != 1 or response.question[0] != query.question[0]:
        raise ValueError("response question does not match request")
    if response.rcode() != expected_rcode:
        raise ValueError(f"unexpected rcode: expected {dns.rcode.to_text(expected_rcode)}, got {dns.rcode.to_text(response.rcode())}")
    if expected_ip is not None:
        answers = [str(item) for rrset in response.answer for item in rrset]
        if expected_ip not in answers:
            raise ValueError(f"expected A answer {expected_ip}, got {answers}")


def summarize_samples(name: str, samples: list[dict], elapsed_s: float, *, report: bool = True) -> dict:
    latencies = [sample["latency_ns"] / 1_000_000 for sample in samples if sample["status"] == "success"]
    ordered = sorted(latencies)
    errors = [sample for sample in samples if sample["status"] != "success"]
    summary = {
        "name": name,
        "requests": len(samples),
        "successes": len(latencies),
        "error_count": len(errors),
        "timeout_count": sum(sample["status"] == "timeout" for sample in errors),
        "validation_failure_count": sum(sample["status"] == "validation_error" for sample in errors),
        "transport_error_count": sum(sample["status"] == "transport_error" for sample in errors),
        "errors": errors,
        "elapsed_s": elapsed_s,
        "qps": len(latencies) / elapsed_s if elapsed_s else 0.0,
        "percentiles_ms": {
            "p50": percentile(ordered, 0.50),
            "p90": percentile(ordered, 0.90),
            "p95": percentile(ordered, 0.95),
            "p99": percentile(ordered, 0.99),
            "max": ordered[-1] if ordered else None,
        },
    }
    p = summary["percentiles_ms"]
    if report and ordered:
        print(f"  {name}: {len(latencies)}/{len(samples)} ok, {summary['qps']:.1f} QPS, p50={p['p50']:.3f}ms p95={p['p95']:.3f}ms p99={p['p99']:.3f}ms")
    elif report:
        print(f"  {name}: 0/{len(samples)} ok")
    return summary


async def measure_queries(
    name: str,
    query_fn: Callable[[dns.message.Message], Awaitable[dns.message.Message]],
    plan: list[tuple[str, int, str | None]],
    *,
    warmup: int = 0,
    concurrency: int = 1,
    rate: float | None = None,
    report: bool = True,
) -> dict:
    for i in range(warmup):
        query_name, expected_rcode, expected_ip = plan[i % len(plan)]
        query = make_query(query_name)
        response = await query_fn(query)
        validate_dns_response(query, response, expected_rcode, expected_ip)

    semaphore = asyncio.Semaphore(concurrency)
    pace_lock = asyncio.Lock()
    next_start = time.perf_counter()

    async def one(index: int, spec: tuple[str, int, str | None]) -> dict:
        nonlocal next_start
        query_name, expected_rcode, expected_ip = spec
        async with semaphore:
            if rate:
                async with pace_lock:
                    delay = max(0.0, next_start - time.perf_counter())
                    next_start = max(next_start, time.perf_counter()) + 1.0 / rate
                if delay:
                    await asyncio.sleep(delay)
            query = make_query(query_name)
            started = time.perf_counter_ns()
            try:
                response = await query_fn(query)
                latency = time.perf_counter_ns() - started
                validate_dns_response(query, response, expected_rcode, expected_ip)
                return {
                    "index": index,
                    "name": query_name,
                    "request_id": query.id,
                    "response_id": response.id,
                    "rcode": dns.rcode.to_text(response.rcode()),
                    "latency_ns": latency,
                    "status": "success",
                }
            except Exception as error:
                if isinstance(error, (asyncio.TimeoutError, httpx.TimeoutException)):
                    status = "timeout"
                elif isinstance(error, ValueError):
                    status = "validation_error"
                else:
                    status = "transport_error"
                error_type = type(error).__name__
                error_message = str(error)
            return {
                "index": index,
                "name": query_name,
                "latency_ns": time.perf_counter_ns() - started,
                "status": status,
                "error_type": error_type,
                "error": error_message,
            }

    started = time.perf_counter()
    samples = await asyncio.gather(*(one(index, spec) for index, spec in enumerate(plan)))
    elapsed = time.perf_counter() - started
    return {"samples": samples, "summary": summarize_samples(name, samples, elapsed, report=report)}


def deterministic_plans(seed: int, count: int, prefix: str) -> dict[str, list[tuple[str, int, str | None]]]:
    rng = random.Random(seed)
    hot = [("example.com", dns.rcode.NOERROR, None)] * count
    hot_negative = [(f"negative-{prefix}.invalid", dns.rcode.NXDOMAIN, None)] * count
    unique = [(f"miss-{prefix}-{index}-{rng.getrandbits(32):08x}.invalid", dns.rcode.NXDOMAIN, None) for index in range(count)]
    mixed = []
    for index in range(count):
        choice = index % 4
        if choice == 0:
            mixed.append(("static.perf.home", dns.rcode.NOERROR, "192.0.2.10"))
        elif choice == 1:
            mixed.append(("example.com", dns.rcode.NOERROR, None))
        elif choice == 2:
            mixed.append((f"negative-{prefix}.invalid", dns.rcode.NXDOMAIN, None))
        else:
            mixed.append(unique[index])
    rng.shuffle(mixed)
    identical_name = f"identical-{prefix}.invalid"
    return {
        "static": [("static.perf.home", dns.rcode.NOERROR, "192.0.2.10")] * count,
        "blocked": [("blocked.perf.invalid", dns.rcode.NXDOMAIN, None)] * count,
        "hot-positive": hot,
        "hot-negative": hot_negative,
        "cacheable-negative-miss": unique,
        "mixed": mixed,
        "concurrent-identical-miss": [(identical_name, dns.rcode.NXDOMAIN, None)] * count,
    }


class PersistentDohClient:
    def __init__(self, url: str, *, verify: str | bool, timeout: float, concurrency: int):
        self.url = url
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            verify=verify,
            http2=False,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        )
        self.http_versions: set[str] = set()
        self.connection_ms: float | None = None

    async def __aenter__(self) -> "PersistentDohClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.aclose()

    async def query(self, query: dns.message.Message) -> dns.message.Message:
        started = time.perf_counter_ns()
        response = await self.client.post(
            self.url,
            content=query.to_wire(),
            headers={"content-type": "application/dns-message", "accept": "application/dns-message"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        if self.connection_ms is None:
            self.connection_ms = (time.perf_counter_ns() - started) / 1_000_000
        content_type = response.headers.get("content-type", "").split(";", 1)[0]
        if content_type != "application/dns-message":
            raise ValueError(f"unexpected DoH content type {content_type!r}")
        self.http_versions.add(response.http_version)
        return dns.message.from_wire(response.content)


def upstream_configuration(mode: str) -> tuple[list[str], str]:
    if mode == "doh":
        return [REAL_UPSTREAM_DOH], "sequential"
    if mode == "dot":
        return [REAL_UPSTREAM_DOT], "sequential"
    if mode == "hedged":
        return [REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT], "hedged"
    return [REAL_UPSTREAM_DOH, REAL_UPSTREAM_DOT], "sequential"


async def run_local_slot(binary: Path, label: str, logical_round: int, slot: int, upstream_mode: str) -> dict:
    dot_port, doh_port = free_port(), free_port()
    upstreams, strategy = upstream_configuration(upstream_mode)
    config = render_config(
        dot_port=dot_port,
        doh_port=doh_port,
        upstream_urls=upstreams,
        strategy=strategy,
        blocklist_domains=["blocked.perf.invalid"],
        static_hosts={"static.perf.home": "192.0.2.10"},
        cache_max_bytes=64 * 1024,
    )
    prefix = f"r{logical_round}-{PERF_OPTIONS.seed}"
    results = []
    server_name = f"perf-{label}-{upstream_mode}-r{logical_round}-s{slot}"
    with DnsRsServer(server_name, config, rust_log="warn", binary=binary, ports=(dot_port, doh_port)) as server:
        ctx = ssl.create_default_context(cafile=str(CERT_PATH))
        async with PersistentDotClient("127.0.0.1", dot_port, "localhost", ctx, PERF_OPTIONS.timeout) as dot_client, PersistentDohClient(
            f"https://localhost:{doh_port}/dns-query",
            verify=str(CERT_PATH),
            timeout=PERF_OPTIONS.timeout,
            concurrency=PERF_OPTIONS.concurrency,
        ) as doh_client:
            await dot_client.query(make_query("example.com"))
            doh_setup_started = time.perf_counter_ns()
            await doh_client.query(make_query("example.com"))
            doh_connection_ms = (time.perf_counter_ns() - doh_setup_started) / 1_000_000
            before = server.resource_snapshot()
            for transport, query_fn in (("dot", dot_client.query), ("doh", doh_client.query)):
                transport_prefix = f"{prefix}-{transport}"
                plans = deterministic_plans(PERF_OPTIONS.seed + logical_round, PERF_OPTIONS.requests, transport_prefix)
                await query_fn(make_query(f"negative-{transport_prefix}.invalid"))
                for workload, plan in plans.items():
                    concurrency = PERF_OPTIONS.concurrency if workload == "concurrent-identical-miss" else 1
                    warmup = PERF_OPTIONS.warmup if workload in {"static", "blocked", "hot-positive", "hot-negative"} else 0
                    if warmup:
                        await measure_queries(
                            f"{label}/{upstream_mode}/{transport}/{workload}/warmup",
                            query_fn,
                            [plan[index % len(plan)] for index in range(warmup)],
                            concurrency=concurrency,
                            report=False,
                        )
                    workload_before = server.resource_snapshot()
                    measured = await measure_queries(
                        f"{label}/{upstream_mode}/{transport}/{workload}",
                        query_fn,
                        plan,
                        concurrency=concurrency,
                    )
                    workload_after = server.resource_snapshot()
                    measured["resources"] = resource_delta(
                        workload_before,
                        workload_after,
                        measured["summary"]["successes"],
                    )
                    results.append({"transport": transport, "workload": workload, **measured})
            after = server.resource_snapshot()
            successes = sum(result["summary"]["successes"] for result in results)
            resources = resource_delta(before, after, successes)
            http_versions = sorted(doh_client.http_versions)
            connection_setup_ms = {"dot": dot_client.connection_ms, "doh": doh_connection_ms}
        alive = server.is_alive()
    return {
        "label": label,
        "logical_round": logical_round,
        "slot": slot,
        "upstream_mode": upstream_mode,
        "results": results,
        "resources": resources,
        "http_versions": http_versions,
        "connection_setup_ms": connection_setup_ms,
        "server_alive_after_measurement": alive,
        "server_returncode": server.returncode,
        "server_forced_kill": server.forced_kill,
    }


def paired_summaries(runs: list[dict], label_a: str, label_b: str) -> list[dict]:
    grouped: dict[tuple[int, str, str, str], dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    p99s: dict[tuple[int, str, str, str], dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    cpu: dict[tuple[int, str, str, str], dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for run in runs:
        for result in run["results"]:
            key = (run["logical_round"], run["upstream_mode"], result["transport"], result["workload"])
            grouped[key][run["label"]].append(result["summary"]["qps"])
            p99 = result["summary"]["percentiles_ms"]["p99"]
            if p99 is not None:
                p99s[key][run["label"]].append(p99)
            cpu_per_success = (result.get("resources") or {}).get("cpu_us_per_success")
            if cpu_per_success is not None:
                cpu[key][run["label"]].append(cpu_per_success)
    output = []
    for key, labels in sorted(grouped.items()):
        if label_a not in labels or label_b not in labels:
            continue
        a = sum(labels[label_a]) / len(labels[label_a])
        b = sum(labels[label_b]) / len(labels[label_b])
        a_p99_values = p99s[key].get(label_a, [])
        b_p99_values = p99s[key].get(label_b, [])
        a_p99 = sum(a_p99_values) / len(a_p99_values) if a_p99_values else None
        b_p99 = sum(b_p99_values) / len(b_p99_values) if b_p99_values else None
        a_cpu_values = cpu[key].get(label_a, [])
        b_cpu_values = cpu[key].get(label_b, [])
        a_cpu = sum(a_cpu_values) / len(a_cpu_values) if a_cpu_values else None
        b_cpu = sum(b_cpu_values) / len(b_cpu_values) if b_cpu_values else None
        output.append({
            "logical_round": key[0],
            "upstream_mode": key[1],
            "transport": key[2],
            "workload": key[3],
            "baseline_qps": a,
            "candidate_qps": b,
            "qps_delta_percent": (b - a) / a * 100 if a else None,
            "baseline_p99_ms": a_p99,
            "candidate_p99_ms": b_p99,
            "p99_delta_percent": (b_p99 - a_p99) / a_p99 * 100 if a_p99 and b_p99 is not None else None,
            "baseline_cpu_us_per_success": a_cpu,
            "candidate_cpu_us_per_success": b_cpu,
            "cpu_delta_percent": (b_cpu - a_cpu) / a_cpu * 100 if a_cpu and b_cpu is not None else None,
        })
    return output


def mean_present(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return sum(present) / len(present) if present else None


def paired_live_summaries(runs: list[dict]) -> list[dict]:
    grouped: dict[tuple[int, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for run in runs:
        grouped[(run["logical_round"], run["transport"])][run["label"]].append(run["summary"])
    output = []
    for (logical_round, transport), labels in sorted(grouped.items()):
        if "fly" not in labels or "cloudflare" not in labels:
            continue
        fly_qps = mean_present([item["qps"] for item in labels["fly"]])
        cloudflare_qps = mean_present([item["qps"] for item in labels["cloudflare"]])
        fly_p99 = mean_present([item["percentiles_ms"]["p99"] for item in labels["fly"]])
        cloudflare_p99 = mean_present([item["percentiles_ms"]["p99"] for item in labels["cloudflare"]])
        output.append({
            "logical_round": logical_round,
            "transport": transport,
            "fly_qps": fly_qps,
            "cloudflare_qps": cloudflare_qps,
            "fly_vs_cloudflare_qps_delta_percent": (fly_qps - cloudflare_qps) / cloudflare_qps * 100 if fly_qps is not None and cloudflare_qps else None,
            "fly_p99_ms": fly_p99,
            "cloudflare_p99_ms": cloudflare_p99,
            "fly_vs_cloudflare_p99_delta_percent": (fly_p99 - cloudflare_p99) / cloudflare_p99 * 100 if fly_p99 is not None and cloudflare_p99 else None,
        })
    return output


def evidence_document(mode: str, runs: list[dict], binaries: list[dict], extra: dict | None = None) -> dict:
    git_status = command_text("git", "-C", str(REPO_ROOT), "status", "--short")
    metadata = {
        "schema_version": 1,
        "mode": mode,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "invocation": sys.argv,
        "hostname": platform.node(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
        "cpu_model": next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), None) if Path("/proc/cpuinfo").exists() else None,
        "git_commit": command_text("git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"),
        "git_dirty": bool(git_status),
        "git_status": git_status,
        "rustc": command_text("rustc", "--version", "--verbose"),
        "cargo": command_text("cargo", "--version"),
        "perf_available": shutil.which("perf") is not None,
        "rust_log": "warn" if mode == "perf-local" else None,
        "connection_policy": {
            "dot": "one persistent multiplexed TLS connection per target and slot; handshake measured separately",
            "doh": "one persistent httpx.AsyncClient per target and slot; HTTP/1.1; matching connection limits",
        },
        "build": {
            "profile": "release",
            "locked": True,
            "features": "default (dot,doh)",
            "lto": True,
            "codegen_units": 1,
            "strip": True,
            "rustflags": os.environ.get("RUSTFLAGS", ""),
        },
        "settings": {
            "seed": PERF_OPTIONS.seed,
            "rounds": PERF_OPTIONS.rounds,
            "requests": PERF_OPTIONS.requests,
            "warmup": PERF_OPTIONS.warmup,
            "concurrency": PERF_OPTIONS.concurrency,
            "timeout_s": PERF_OPTIONS.timeout,
            "live_rate_qps_aggregate": PERF_OPTIONS.live_rate,
        },
        "limitations": [
            "public-network latency includes client routing, Fly placement, TLS, and upstream RTT",
            "Linux /proc CPU is process-wide and does not attribute cost to functions",
            "perf profiling is unavailable when perf_available is false",
        ],
    }
    if extra:
        metadata.update(extra)
    return {"metadata": metadata, "binaries": binaries, "runs": runs}


def write_evidence(mode: str, evidence: dict) -> Path:
    path = PERF_OPTIONS.output or RUN_DIR / f"{mode}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"  evidence: {path}")
    return path


async def run_sweep_probe(binary: Path, label: str) -> dict:
    dot_port, doh_port = free_port(), free_port()
    config = render_config(
        dot_port=dot_port,
        doh_port=doh_port,
        upstream_urls=[REAL_UPSTREAM_DOH],
        static_hosts={"static.perf.home": "192.0.2.10"},
        cache_max_bytes=4096,
    )
    samples = []
    with DnsRsServer(f"perf-{label}-sweep", config, rust_log="warn", binary=binary, ports=(dot_port, doh_port)) as server:
        ctx = ssl.create_default_context(cafile=str(CERT_PATH))
        async with PersistentDotClient("127.0.0.1", dot_port, "localhost", ctx, PERF_OPTIONS.timeout) as dot_client:
            before = server.resource_snapshot()
            deadline = time.monotonic() + PERF_OPTIONS.sweep_seconds
            index = 0
            while time.monotonic() < deadline:
                plan = [
                    ("static.perf.home", dns.rcode.NOERROR, "192.0.2.10")
                    if index % 4 == 0
                    else (f"sweep-{PERF_OPTIONS.seed}-{index}.invalid", dns.rcode.NXDOMAIN, None)
                ]
                measured = await measure_queries(f"{label}/sweep-over-30s", dot_client.query, plan, report=False)
                samples.extend(measured["samples"])
                index += 1
                await asyncio.sleep(0.9)
            elapsed = PERF_OPTIONS.sweep_seconds
            after = server.resource_snapshot()
            summary = summarize_samples(f"{label}/sweep-over-30s", samples, elapsed)
            resources = resource_delta(before, after, summary["successes"])
            alive = server.is_alive()
    return {
        "label": label,
        "workload": "sweep-over-30s",
        "duration_s": PERF_OPTIONS.sweep_seconds,
        "samples": samples,
        "summary": summary,
        "resources": resources,
        "server_alive_after_measurement": alive,
        "server_returncode": server.returncode,
        "server_forced_kill": server.forced_kill,
    }


async def scenario_perf_local() -> bool:
    section("perf-local: reproducible A-B-B-A")
    labels = [(PERF_OPTIONS.label_a, PERF_OPTIONS.binary_a)]
    if PERF_OPTIONS.binary_b:
        labels.append((PERF_OPTIONS.label_b, PERF_OPTIONS.binary_b))
    modes = ["doh", "dot", "sequential", "hedged"]
    runs = []
    for logical_round in range(PERF_OPTIONS.rounds):
        if len(labels) == 1:
            order = labels
        elif logical_round % 2 == 0:
            order = [labels[0], labels[1], labels[1], labels[0]]
        else:
            order = [labels[1], labels[0], labels[0], labels[1]]
        for slot, (label, binary) in enumerate(order):
            for upstream_mode in modes:
                runs.append(await run_local_slot(binary, label, logical_round, slot, upstream_mode))

    binaries = [binary_metadata(label, binary) for label, binary in labels]
    sweep_runs = [await run_sweep_probe(binary, label) for label, binary in labels]
    evidence = evidence_document("perf-local", runs, binaries)
    evidence["sweep_runs"] = sweep_runs
    if len(labels) == 2:
        evidence["paired_summaries"] = paired_summaries(runs, labels[0][0], labels[1][0])
    write_evidence("perf-local", evidence)
    errors = sum(result["summary"]["error_count"] for run in runs for result in run["results"])
    errors += sum(run["summary"]["error_count"] for run in sweep_runs)
    alive = all(run["server_alive_after_measurement"] for run in runs) and all(run["server_alive_after_measurement"] for run in sweep_runs)
    return check("local performance runs completed with valid responses", errors == 0 and alive, detail=f"errors={errors}")


async def scenario_perf_live() -> bool:
    section("perf-live: paired Fly vs Cloudflare DoT and DoH")
    fly_doh_url = PERF_OPTIONS.fly_doh_url or f"https://{PERF_OPTIONS.fly_host}/dns-query"
    targets = {
        "fly": {
            "dot": (PERF_OPTIONS.fly_host, 853, PERF_OPTIONS.fly_host),
            "doh": fly_doh_url,
        },
        "cloudflare": {
            "dot": (PERF_OPTIONS.cloudflare_dot_host, 853, "cloudflare-dns.com"),
            "doh": PERF_OPTIONS.cloudflare_doh_url,
        },
    }
    runs = []
    interval = 1.0 / PERF_OPTIONS.live_rate
    next_start = time.perf_counter()
    for logical_round in range(PERF_OPTIONS.rounds):
        order = ["fly", "cloudflare", "cloudflare", "fly"] if logical_round % 2 == 0 else ["cloudflare", "fly", "fly", "cloudflare"]
        clients = []
        try:
            for transport in ("dot", "doh"):
                for slot, label in enumerate(order):
                    target = targets[label]
                    if transport == "dot":
                        client = PersistentDotClient(*target["dot"], ssl.create_default_context(), PERF_OPTIONS.timeout)
                    else:
                        client = PersistentDohClient(target["doh"], verify=True, timeout=PERF_OPTIONS.timeout, concurrency=1)
                    await client.__aenter__()
                    clients.append(client)
                    samples = []
                    started = time.perf_counter()
                    for index in range(PERF_OPTIONS.requests):
                        delay = max(0.0, next_start - time.perf_counter())
                        if delay:
                            await asyncio.sleep(delay)
                        next_start = max(next_start, time.perf_counter()) + interval
                        name = WARM_DOMAINS[(logical_round + index) % len(WARM_DOMAINS)]
                        measured = await measure_queries(
                            f"live/{transport}/{label}/r{logical_round}/s{slot}",
                            client.query,
                            [(name, dns.rcode.NOERROR, None)],
                            report=False,
                        )
                        samples.extend(measured["samples"])
                    elapsed = time.perf_counter() - started
                    runs.append({
                        "label": label,
                        "logical_round": logical_round,
                        "slot": slot,
                        "transport": transport,
                        "connection_setup_ms": client.connection_ms,
                        "http_versions": sorted(client.http_versions) if transport == "doh" else [],
                        "samples": samples,
                        "summary": summarize_samples(f"live/{transport}/{label}/r{logical_round}/s{slot}", samples, elapsed),
                    })
        finally:
            for client in reversed(clients):
                await client.__aexit__(None, None, None)

    evidence = evidence_document("perf-live", runs, [], {"targets": targets})
    evidence["paired_summaries"] = paired_live_summaries(runs)
    write_evidence("perf-live", evidence)
    errors = sum(run["summary"]["error_count"] for run in runs)
    return check("live performance runs completed with valid responses", errors == 0, detail=f"errors={errors}")


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
    "perf-local": scenario_perf_local,
    "perf-live": scenario_perf_live,
}

MEASUREMENT_SCENARIOS = {"perf-local", "perf-live"}


async def run(selected: list[str]) -> int:
    local_binaries = [PERF_OPTIONS.binary_a]
    if PERF_OPTIONS.binary_b:
        local_binaries.append(PERF_OPTIONS.binary_b)
    needs_local_server = any(name != "perf-live" for name in selected)
    missing = [binary for binary in local_binaries if needs_local_server and not binary.is_file()]
    if missing:
        print(f"error: missing binary: {missing[0]}", file=sys.stderr)
        return 2
    if needs_local_server and shutil.which("openssl") is None:
        print("error: openssl not found on PATH (needed to generate the test cert)", file=sys.stderr)
        return 2
    if PERF_OPTIONS.output and len(selected) > 1:
        print("error: --output requires exactly one selected scenario", file=sys.stderr)
        return 2
    if needs_local_server:
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


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenarios", nargs="*", default=["all"], choices=[*SCENARIOS, "all"], help="which scenarios to run")
    parser.add_argument("--binary-a", type=Path, default=BINARY, help="baseline or single local binary")
    parser.add_argument("--binary-b", type=Path, help="candidate local binary for paired runs")
    parser.add_argument("--label-a", default="baseline")
    parser.add_argument("--label-b", default="candidate")
    parser.add_argument("--output", type=Path, help="JSON evidence path")
    parser.add_argument("--seed", type=int, default=PERF_SEED)
    parser.add_argument("--rounds", type=positive_int, default=8)
    parser.add_argument("--requests", type=positive_int, default=PERF_REQUESTS)
    parser.add_argument("--warmup", type=positive_int, default=PERF_WARMUP)
    parser.add_argument("--concurrency", type=positive_int, default=8)
    parser.add_argument("--timeout", type=positive_float, default=8.0)
    parser.add_argument("--live-rate", type=positive_float, default=PERF_LIVE_RATE, help="aggregate public requests per second")
    parser.add_argument("--fly-host", default=os.environ.get("E2E_PERF_FLY_HOST", "dns-rs-cold-hollow-7445.fly.dev"))
    parser.add_argument("--fly-doh-url")
    parser.add_argument("--cloudflare-dot-host", default=os.environ.get("E2E_PERF_CLOUDFLARE_IP", "1.1.1.1"))
    parser.add_argument("--cloudflare-doh-url", default=REAL_UPSTREAM_DOH)
    parser.add_argument("--sweep-seconds", type=positive_float, default=31.0)
    args = parser.parse_args()
    if args.binary_b and args.label_a == args.label_b:
        parser.error("--label-a and --label-b must differ")
    if "perf-live" in args.scenarios and args.live_rate > 1.0:
        parser.error("--live-rate must be <= 1 request/second aggregate")

    global PERF_OPTIONS
    PERF_OPTIONS = PerfOptions(
        binary_a=args.binary_a.expanduser().resolve(),
        binary_b=args.binary_b.expanduser().resolve() if args.binary_b else None,
        label_a=args.label_a,
        label_b=args.label_b,
        output=args.output.expanduser().resolve() if args.output else None,
        seed=args.seed,
        rounds=args.rounds,
        requests=args.requests,
        warmup=args.warmup,
        concurrency=args.concurrency,
        timeout=args.timeout,
        live_rate=args.live_rate,
        fly_host=args.fly_host,
        fly_doh_url=args.fly_doh_url or "",
        cloudflare_dot_host=args.cloudflare_dot_host,
        cloudflare_doh_url=args.cloudflare_doh_url,
        sweep_seconds=args.sweep_seconds,
    )
    selected = [name for name in SCENARIOS if name not in MEASUREMENT_SCENARIOS] if "all" in args.scenarios else args.scenarios
    code = asyncio.run(run(selected))
    sys.exit(code)


if __name__ == "__main__":
    main()
