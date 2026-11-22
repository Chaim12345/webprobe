import socketserver, base64, hashlib, struct, threading, socket, json
ROOT='/downloads/burp-comparison/followup/'
class WS(socketserver.BaseRequestHandler):
 def handle(self):
  data=b''
  while b'\r\n\r\n' not in data: data+=self.request.recv(4096)
  headers=dict(line.split(b':',1) for line in data.split(b'\r\n')[1:] if b':' in line)
  key=headers[b'Sec-WebSocket-Key'].strip()
  accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
  self.request.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
  def exact(n):
   out=b''
   while len(out)<n:
    part=self.request.recv(n-len(out))
    if not part: raise EOFError
    out+=part
   return out
  try:
   while True:
    a,b=exact(2); n=b&127
    if n==126: n=struct.unpack('!H',exact(2))[0]
    if n==127: n=struct.unpack('!Q',exact(8))[0]
    mask=exact(4) if b&128 else None
    payload=exact(n)
    if mask: payload=bytes(v^mask[i%4] for i,v in enumerate(payload))
    if a&15==8: break
    with open(ROOT+'ws-origin.jsonl','a') as f: f.write(json.dumps({'opcode':a&15,'payload':payload.decode(errors='replace')})+'\n')
    self.request.sendall(bytes([a, len(payload)])+payload)
  except (EOFError,ConnectionResetError,BrokenPipeError): pass
class Server(socketserver.ThreadingTCPServer): allow_reuse_address=True; daemon_threads=True
Server(('127.0.0.1',18766),WS).serve_forever()
