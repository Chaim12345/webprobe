#!/usr/bin/env python3
"""Loaded-proxy harness (perf lane, 2026-11-22).

Loopback origin (threaded, keep-alive, fixed 1000-byte body) behind the
headless webprobe proxy example. Each client request is a fresh TCP
connection through the proxy (the proxy serves one request per client
connection), absolute-form GET, response status and full body validated.

Usage: drive.py <proxy-binary> <label> <outdir>
One sample: CONCURRENCY x REPEATS runs of REQUESTS requests, alternating
with other labels is the caller's job. JSON per run lands in <outdir>.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"x" * 1000
ORIGIN_PORT = 19099
PROXY_PORT = 18080
REQUESTS = int(os.environ.get("PERF_REQUESTS", "2048"))
CONCURRENCIES = [int(c) for c in os.environ.get("PERF_CONC", "16,64,128").split(",")]
REPEATS = int(os.environ.get("PERF_REPEATS", "3"))
WARMUP = 288


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


def one_request(i):
    """One exchange through the proxy; returns latency seconds."""
    t0 = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=30)
    s.sendall(b"GET http://127.0.0.1:%d/x?i=%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
              % (ORIGIN_PORT, i, ORIGIN_PORT))
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    dt = time.perf_counter() - t0
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200"), head[:80]
    assert body == BODY, len(body)
    return dt


def run(concurrency, total):
    lock = threading.Lock()
    counter = [0]
    lats = []
    errors = [0]

    def worker():
        while True:
            with lock:
                i = counter[0]
                counter[0] += 1
            if i >= total:
                return
            try:
                dt = one_request(i)
                with lock:
                    lats.append(dt)
            except Exception:
                with lock:
                    errors[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - start
    lats.sort()
    if not lats:
        return None
    p50 = lats[len(lats) // 2] * 1000
    p95 = lats[int(len(lats) * 0.95)] * 1000
    return {
        "concurrency": concurrency,
        "requests": total,
        "ok": len(lats),
        "errors": errors[0],
        "wall_s": round(wall, 3),
        "conn_per_s": round(len(lats) / wall, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
    }


def main():
    binary, label, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    origin = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    proxy = subprocess.Popen([binary, str(PROXY_PORT)], stdout=subprocess.PIPE, text=True)
    try:
        line = proxy.stdout.readline().strip()
        assert line == "READY %d" % PROXY_PORT, line
        for i in range(WARMUP):
            one_request(i)
        results = []
        for c in CONCURRENCIES:
            for r in range(REPEATS):
                res = run(c, REQUESTS)
                res["repeat"] = r
                results.append(res)
                print(json.dumps({"label": label, **res}), flush=True)
        with open(os.path.join(outdir, "%s.json" % label), "w") as f:
            json.dump({"label": label, "results": results}, f, indent=2)
    finally:
        proxy.kill()
        origin.shutdown()


if __name__ == "__main__":
    main()
