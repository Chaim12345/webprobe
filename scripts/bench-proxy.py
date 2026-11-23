#!/usr/bin/env python3
"""Owned loopback HTTP fixture and connection-per-request proxy benchmark.
Usage: python3 scripts/bench-proxy.py BASELINE_BINARY STACK_BINARY > results.json
Linux /proc supplies sampled proxy RSS and thread counts. Python stdlib only.
"""
import concurrent.futures as cf
import http.server
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time

class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = b'webprobe-local-benchmark\n' * 40
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

class FixtureServer(http.server.ThreadingHTTPServer):
    request_queue_size = 256

origin = FixtureServer(('127.0.0.1', 0), Origin)
threading.Thread(target=origin.serve_forever, daemon=True).start()
origin_port = origin.server_port

def sample(pid):
    values = {}
    with open(f'/proc/{pid}/status') as f:
        for line in f:
            key, _, value = line.partition(':')
            if key in ('VmRSS', 'Threads'):
                values[key] = int(value.strip().split()[0])
    return values['VmRSS'], values['Threads']

def run(binary, concurrency, repeat):
    proc = subprocess.Popen([os.path.abspath(binary)] + sys.argv[3:], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(proc.stdout.readline())
        def exchange(_):
            start = time.perf_counter()
            with socket.create_connection(('127.0.0.1', port), timeout=10) as sock:
                sock.settimeout(10)
                sock.sendall((f'GET http://127.0.0.1:{origin_port}/fixture HTTP/1.1\r\n'
                              f'Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n').encode())
                parts = []
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    parts.append(data)
            response = b''.join(parts)
            assert response.startswith(b'HTTP/1.1 200'), response[:100]
            assert response.endswith(b'webprobe-local-benchmark\n' * 40), len(response)
            return (time.perf_counter() - start) * 1000
        for i in range(8):
            exchange(i)
        idle_rss, idle_threads = sample(proc.pid)
        readings = []
        stop = threading.Event()
        def monitor():
            while not stop.wait(0.005):
                readings.append(sample(proc.pid))
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.start()
        count = 128
        started = time.perf_counter()
        try:
            with cf.ThreadPoolExecutor(max_workers=concurrency) as pool:
                latencies = list(pool.map(exchange, range(count)))
        finally:
            elapsed = time.perf_counter() - started
            stop.set()
            monitor_thread.join()
        readings.append(sample(proc.pid))
        latencies.sort()
        return dict(binary=os.path.basename(binary), concurrency=concurrency, repeat=repeat,
                    requests=count, failures=0, seconds=elapsed,
                    connections_per_second=count / elapsed,
                    latency_p50_ms=statistics.median(latencies),
                    latency_p95_ms=latencies[int(len(latencies)*0.95)],
                    idle_rss_kib=idle_rss, peak_rss_kib=max(r[0] for r in readings),
                    idle_threads=idle_threads, peak_threads=max(r[1] for r in readings))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

results = []
for concurrency in (1, 16, 64):
    for repeat in range(3):
        # Alternate order to reduce systematic warm-cache/order bias.
        binaries = sys.argv[1:3] if repeat % 2 == 0 else list(reversed(sys.argv[1:3]))
        for binary in binaries:
            results.append(run(binary, concurrency, repeat))
origin.shutdown()
print(json.dumps(dict(platform=platform.platform(), cpu_count=os.cpu_count(),
                     python=sys.version, listener_args=sys.argv[3:], samples=results), indent=2))
