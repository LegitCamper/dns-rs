# /// script
# requires-python = ">=3.11"
# dependencies = ["dnspython>=2.6", "httpx>=0.27"]
# ///
"""Paired persistent-DoT benchmarks with local, certificate-verified DoH upstreams.

uv run tests/e2e/perf_tail.py --baseline PATH --candidate PATH --rounds 8
No public DNS traffic. SSL_CERT_FILE trusts only the test CA in child processes.
"""

import argparse
import asyncio
import collections
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

import dns.message
import dns.rcode
import dns.rrset

sys.dont_write_bytecode = True
import harness as h

TLS_DIR = h.RUN_DIR / "latency"


def upstream_certificate():
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(TLS_DIR / "upstream.key"), "-out", str(TLS_DIR / "upstream.csr"),
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(TLS_DIR / "upstream.csr"),
        "-CA", str(h.CERT_PATH), "-CAkey", str(h.KEY_PATH), "-set_serial", "1",
        "-copy_extensions", "copy", "-days", "1", "-out", str(TLS_DIR / "upstream.pem"),
    ], check=True, capture_output=True)


class Upstream:
    def __init__(self, delay):
        self.calls = collections.Counter()
        self.lock = threading.Lock()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self):
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

            def setup(self):
                super().setup()
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            def do_POST(self):
                size = int(self.headers["Content-Length"])
                if not 0 < size <= 65535:
                    self.send_error(400)
                    return
                query = dns.message.from_wire(self.rfile.read(size))
                name = str(query.question[0].name)
                with owner.lock:
                    owner.calls[name] += 1
                time.sleep(0 if name.startswith("fill-") else delay)
                response = dns.message.make_response(query)
                ttl = 2 if name.startswith("periodic-") else 1 if name.startswith("fill-") else 300
                response.answer.append(dns.rrset.from_text(name, ttl, "IN", "A", "192.0.2.1"))
                wire = response.to_wire()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/dns-message")
                    self.send_header("Content-Length", str(len(wire)))
                    self.end_headers()
                    self.wfile.write(wire)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # A losing hedge can close its request.

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(TLS_DIR / "upstream.pem", TLS_DIR / "upstream.key")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://localhost:{self.server.server_port}/dns-query"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def count(self, names):
        with self.lock:
            return sum(self.calls[name] for name in names)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@contextmanager
def server(binary, label, urls, strategy="hedged", blocklist_urls=None):
    ports = h.free_port(), h.free_port()
    config = h.render_config(
        dot_port=ports[0], doh_port=ports[1], upstream_urls=urls, strategy=strategy,
        cache_max_bytes=64 * 1024 * 1024, static_hosts={"static.test": "192.0.2.1"},
        blocklist_urls=blocklist_urls,
    )
    if blocklist_urls:
        config = config.replace("refresh_interval_secs = 43200", "refresh_interval_secs = 5", 1)
    process = h.DnsRsServer(f"tail-{label}", config, rust_log="warn", binary=binary, ports=ports)
    try:
        with process:
            yield process
    finally:
        (h.RUN_DIR / f"tail-{label}" / "server.log").write_text("\n".join(process.logs))


def client(process):
    return h.PersistentDotClient("127.0.0.1", process.ports[0], "localhost", ssl.create_default_context(cafile=str(h.CERT_PATH)))


def plan(names):
    return [(name, dns.rcode.NOERROR, "192.0.2.1") for name in names]


async def slot(binary, label, round_id, slot_id, fast, slow, requests):
    results = []
    # Same hedged config isolates code overhead for hot hits and ordinary misses.
    with server(binary, f"{label}-{round_id}-{slot_id}", [fast.url]) as process:
        async with client(process) as connection:
            for workload, names, warmup in [
                ("hot", ["hot.test"] * requests, 20),
                ("miss", [f"miss-{i}.test" for i in range(40)], 0),
            ]:
                results.append(await h.measure_queries(workload, connection.query, plan(names), warmup=warmup))
    # Deliberately compare old/new deployment strategies under a slow primary.
    strategy = "sequential" if label == "baseline" else "hedged"
    with server(binary, f"{label}-hedge-{round_id}-{slot_id}", [slow.url, fast.url], strategy) as process:
        async with client(process) as connection:
            results.append(await h.measure_queries("slow-primary", connection.query, plan([f"slow-{i}.test" for i in range(20)])))
    return {"label": label, "round": round_id, "slot": slot_id, "results": results}


async def idle_probe(binary, label, upstream):
    names = [f"periodic-{label}-{i}.test." for i in range(4)]
    with server(binary, f"{label}-idle", [upstream.url]) as process:
        async with client(process) as connection:
            await h.measure_queries("prime", connection.query, plan(names * 2), report=False)
            before = upstream.count(names)
            print(f"{label}: waiting 33s past TTL + stale window", flush=True)
            await asyncio.sleep(33)
            background = upstream.count(names) - before
            before = upstream.count(names)
            result = await h.measure_queries("after-idle", connection.query, plan(names))
            return {"label": label, "background_queries": background,
                    "queries_during_probe": upstream.count(names) - before, **result}


async def maintenance_probe(binary, label, upstream, entries):
    with server(binary, f"{label}-sweep", [upstream.url]) as process:
        async with client(process) as connection:
            fill = await h.measure_queries("fill", connection.query, plan([f"fill-{i}.test" for i in range(entries)]), concurrency=32)
            assert fill["summary"]["error_count"] == 0
            before = process.resource_snapshot()
            samples = []
            started = time.monotonic()
            # Cross two sweep intervals: the first may retain the 30s stale window.
            while time.monotonic() - started < 62:
                result = await h.measure_queries("sweep", connection.query, plan(["static.test"]), report=False)
                samples.extend(result["samples"])
                await asyncio.sleep(0.002)
            elapsed = time.monotonic() - started
            return {"label": label, "entries": entries, "samples": samples,
                    "summary": h.summarize_samples("sweep", samples, elapsed),
                    "process_before": before, "process_after": process.resource_snapshot()}


async def blocklist_probe(binary, label, upstream, entries):
    source = h.LocalHttpTextServer("".join(f"blocked-{i}.test\n" for i in range(entries)).encode())
    try:
        with server(binary, f"{label}-blocklist", [upstream.url], blocklist_urls=[source.url()]) as process:
            # Match the deployment's one CPU while leaving the test client separate.
            cpu = min(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
            if cpu is not None:
                os.sched_setaffinity(process.proc.pid, {cpu})
            async with client(process) as connection:
                samples = []
                started = time.monotonic()
                while time.monotonic() - started < 18:
                    result = await h.measure_queries("blocklist", connection.query, plan(["static.test"]), report=False)
                    samples.extend(result["samples"])
                    await asyncio.sleep(0.002)
                return {"label": label, "entries": entries, "server_cpu": cpu, "samples": samples,
                        "summary": h.summarize_samples("blocklist", samples, time.monotonic() - started)}
    finally:
        source.stop()


async def main(args):
    h.ensure_certs()
    upstream_certificate()
    # Per-process trust; never install certificates into the host trust store.
    os.environ["SSL_CERT_FILE"] = str(h.CERT_PATH)
    fast, slow = Upstream(0.012), Upstream(0.080)
    binaries = [("baseline", args.baseline.resolve()), ("candidate", args.candidate.resolve())]
    evidence = {"binaries": [h.binary_metadata(label, binary) for label, binary in binaries],
                "git_commit": h.command_text("git", "rev-parse", "HEAD"),
                "settings": {"rounds": args.rounds, "requests": args.requests,
                             "connection": "persistent DoT; TLS setup excluded", "fast_delay_ms": 12,
                             "slow_delay_ms": 80, "cache_bytes": 64 * 1024 * 1024,
                             "limitations": "loopback fixture; p99 includes Python client and OS scheduling; slow-primary changes strategy as well as binary"}, "runs": []}
    try:
        for round_id in range(args.rounds):
            order = [0, 1, 1, 0] if round_id % 2 == 0 else [1, 0, 0, 1]
            for slot_id, index in enumerate(order):
                label, binary = binaries[index]
                print(f"round {round_id + 1}/{args.rounds} slot {slot_id} {label}", flush=True)
                evidence["runs"].append(await slot(binary, label, round_id, slot_id, fast, slow, args.requests))
        if not args.skip_idle:
            evidence["idle"] = [await idle_probe(binary, label, fast) for label, binary in binaries]
        if args.sweep_entries:
            evidence["maintenance"] = [await maintenance_probe(binary, label, fast, args.sweep_entries) for label, binary in binaries]
        if args.blocklist_entries:
            evidence["blocklist"] = [await blocklist_probe(binary, label, fast, args.blocklist_entries) for label, binary in binaries]
    finally:
        fast.close()
        slow.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    errors = sum(result["summary"]["error_count"] for run in evidence["runs"] for result in run["results"])
    errors += sum(result["summary"]["error_count"] for key in ("idle", "maintenance", "blocklist") for result in evidence.get(key, []))
    assert errors == 0, f"{errors} invalid or failed responses"
    print(f"Evidence: {args.output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=8, help="paired rounds; zero runs only the optional probes")
    parser.add_argument("--requests", type=h.positive_int, default=1000)
    parser.add_argument("--skip-idle", action="store_true")
    parser.add_argument("--sweep-entries", type=h.positive_int)
    parser.add_argument("--blocklist-entries", type=h.positive_int)
    parser.add_argument("--output", type=Path, default=h.RUN_DIR / "latency" / "perf-tail.json")
    args = parser.parse_args()
    if args.rounds < 0:
        parser.error("--rounds must be nonnegative")
    asyncio.run(main(args))
