from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, threading
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        if self.path.startswith('/token'):
            body = b'ABCD0123456789abcdef\n'
        else:
            body = json.dumps({'method': self.command, 'path': self.path, 'probe_header': self.headers.get('X-Parity-Probe', ''), 'demo_header': self.headers.get('X-Montoya-Demo', '')}, sort_keys=True).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json' if not self.path.startswith('/token') else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Parity-Fixture', 'loopback-only')
        self.end_headers(); self.wfile.write(body)
    def log_message(self, format, *args):
        with open('/downloads/burp-comparison/fixture-requests.log','a') as f: f.write(format % args + '\n')
ThreadingHTTPServer(('127.0.0.1',18765), Handler).serve_forever()
