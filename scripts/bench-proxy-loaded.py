#!/usr/bin/env python3
"""Sustained closed-loop load against an owned loopback HTTP fixture only."""
import argparse
import concurrent.futures as cf
import hashlib
import http.server
import json
import os
import platform
import socket
import statistics
import subprocess
import threading
import time

BODY = b"webprobe-local-benchmark\n" * 40


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_):
        pass


class Fixture(http.server.ThreadingHTTPServer):
    request_queue_size = 512
    daemon_threads = True


def resources(pid):
    result = {}
    with open(f"/proc/{pid}/status") as source:
        for line in source:
            key, _, value = line.partition(":")
            if key in ("VmRSS", "Threads"):
                result[key] = int(value.split()[0])
    return result["VmRSS"], result["Threads"]


def run(binary, fixture_port, args, repeat):
    with subprocess.Popen([os.path.abspath(binary), "--main"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True) as proxy:
        try:
            port = int(proxy.stdout.readline())

            def exchange(_):
                started = time.perf_counter()
                with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
                    client.settimeout(10)
                    client.sendall((f"GET http://127.0.0.1:{fixture_port}/fixture HTTP/1.1\r\n"
                                    f"Host: 127.0.0.1:{fixture_port}\r\n"
                                    "Connection: close\r\n\r\n").encode())
                    response = bytearray()
                    while chunk := client.recv(65536):
                        response.extend(chunk)
                headers, separator, body = response.partition(b"\r\n\r\n")
                if not separator or headers.split(b"\r\n", 1)[0] != b"HTTP/1.1 200 OK" or body != BODY:
                    raise ValueError("incorrect status, framing, or complete response body")
                return (time.perf_counter() - started) * 1000

            for i in range(8):
                exchange(i)
            idle = resources(proxy.pid)
            samples = [idle]
            stop = threading.Event()

            def monitor():
                while not stop.wait(0.005):
                    samples.append(resources(proxy.pid))

            monitor_thread = threading.Thread(target=monitor)
            monitor_thread.start()
            started = time.perf_counter()
            try:
                with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                    latency = sorted(pool.map(exchange, range(args.requests)))
            finally:
                elapsed = time.perf_counter() - started
                stop.set()
                monitor_thread.join()
            samples.append(resources(proxy.pid))
            return dict(binary=os.path.basename(binary), repeat=repeat,
                        concurrency=args.concurrency, requests=args.requests, failures=0,
                        seconds=elapsed, connections_per_second=args.requests / elapsed,
                        latency_p50_ms=statistics.median(latency),
                        latency_p95_ms=latency[int(len(latency) * 0.95)],
                        latency_p99_ms=latency[int(len(latency) * 0.99)],
                        idle_rss_kib=idle[0], peak_rss_kib=max(s[0] for s in samples),
                        idle_threads=idle[1], peak_threads=max(s[1] for s in samples))
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--requests", type=int, default=2048)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if min(args.concurrency, args.requests, args.repeats) < 1:
        parser.error("counts must be positive")
    fixture = Fixture(("127.0.0.1", 0), Origin)
    server_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    server_thread.start()
    results = []
    try:
        for repeat in range(args.repeats):
            binaries = [args.before, args.after]
            if repeat % 2:
                binaries.reverse()
            for binary in binaries:
                result = run(binary, fixture.server_port, args, repeat)
                results.append(result)
    finally:
        fixture.shutdown()
        fixture.server_close()
        server_thread.join()
    binaries = {}
    for binary in (args.before, args.after):
        with open(binary, "rb") as source:
            binaries[os.path.basename(binary)] = hashlib.sha256(source.read()).hexdigest()
    print(json.dumps(dict(platform=platform.platform(), cpu_count=os.cpu_count(),
                          python=platform.python_version(), binary_sha256=binaries,
                          listener="main", body_bytes=len(BODY), samples=results), indent=2))


if __name__ == "__main__":
    main()
