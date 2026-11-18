"""Counting TCP forwarder for the parity bench: listens on 127.0.0.1:LISTEN,
forwards to 127.0.0.1:TARGET (Juice Shop), and counts HTTP request lines
(METHOD SP target SP HTTP/1.x) seen in client->server streams. Writes the
running count to COUNT_FILE. Loopback only."""
import re, socket, sys, threading
LISTEN, TARGET, COUNT_FILE = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
REQ = re.compile(rb'(?:^|\r\n)(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT) \S+ HTTP/1\.[01]\r\n')
lock = threading.Lock(); count = [0]
def bump(n):
    with lock:
        count[0] += n
        open(COUNT_FILE, 'w').write(str(count[0]))
def pipe(src, dst, counting):
    tail = b''
    try:
        while True:
            data = src.recv(65536)
            if not data: break
            if counting:
                buf = tail + data
                bump(len(REQ.findall(buf)) - len(REQ.findall(tail)))
                tail = buf[-256:]
            dst.sendall(data)
    except OSError: pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
def handle(c):
    try: u = socket.create_connection(('127.0.0.1', TARGET))
    except OSError: c.close(); return
    threading.Thread(target=pipe, args=(c, u, True), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c, False), daemon=True).start()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', LISTEN)); srv.listen(256)
bump(0)
while True:
    c, _ = srv.accept(); handle(c)
