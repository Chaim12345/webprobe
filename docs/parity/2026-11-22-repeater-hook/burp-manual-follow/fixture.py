from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, pathlib, threading
ROOT = pathlib.Path('/downloads/burp-comparison/manual-redirect')
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        row = {'server_port': self.server.server_port, 'host': self.headers.get('Host'), 'path': self.path, 'headers': list(self.headers.items())}
        with (ROOT / 'origin.jsonl').open('a') as f:
            f.write(json.dumps(row) + '\n')
        location = 'http://localhost:18769/middle' if self.path == '/start' else '/finish' if self.path == '/middle' else None
        if location:
            self.send_response(302)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            body = json.dumps(row, indent=2).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, *a): pass
for port in [18768, 18769]:
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
