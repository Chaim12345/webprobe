import json, subprocess, sys, threading, time, urllib.request, http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PROXIED=[]; DIRECT=[]
PAGE=b"""<html><head><link rel='stylesheet' href='/s.css'></head><body><img src='/i.png'><script src='/app.js'></script>
<script>fetch('/api').then(r=>r.text());var x=new XMLHttpRequest();x.open('POST','/xhr');x.send('k=v');</script></body></html>"""
class Origin(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _h(self):
        via = self.headers.get("X-Via-Proxy")
        (PROXIED if via else DIRECT).append((self.command,self.path))
        n=int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
        b=PAGE if self.path=="/" else b"x"
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.send_header("Content-Type","text/html" if self.path=="/" else "text/plain"); self.end_headers(); self.wfile.write(b)
    do_GET=do_POST=_h
class Proxy(BaseHTTPRequestHandler):
    SEEN=[]
    def log_message(self,*a): pass
    def _h(self):
        n=int(self.headers.get("Content-Length") or 0); body=self.rfile.read(n) if n else None
        Proxy.SEEN.append((self.command,self.path,body.decode() if body else None))
        u=urllib.request.urlparse(self.path); c=http.client.HTTPConnection(u.hostname,u.port,timeout=5)
        c.request(self.command,(u.path or "/")+("?"+u.query if u.query else ""),body,{"X-Via-Proxy":"1","Host":u.netloc})
        r=c.getresponse(); b=r.read()
        self.send_response(r.status); self.send_header("Content-Length",str(len(b))); self.send_header("Content-Type",r.getheader("Content-Type","text/plain")); self.end_headers(); self.wfile.write(b)
    do_GET=do_POST=_h
def serve(h):
    s=ThreadingHTTPServer(("127.0.0.1",0),h); threading.Thread(target=s.serve_forever,daemon=True).start(); return s.server_address[1]
o=serve(Origin); p=serve(Proxy)
r=subprocess.run([sys.argv[1],"--proxy",f"http://127.0.0.1:{p}","fetch",f"http://127.0.0.1:{o}/","--allow-private-network","--quiet","--wait","2","--eval","document.title"],capture_output=True,text=True,timeout=60)
time.sleep(1)
print(json.dumps({"rc":r.returncode,"through_proxy":sorted(set(PROXIED)),"DIRECT_bypassing_proxy":sorted(set(DIRECT)),"proxy_saw_post_body":[s for s in Proxy.SEEN if s[0]=="POST"],"stderr":r.stderr[-300:]},indent=1))
