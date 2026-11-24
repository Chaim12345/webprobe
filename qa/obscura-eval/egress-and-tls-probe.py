import asyncio, json, ssl, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import websockets
HITS=[]
def mk(name, tls=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self,*a): pass
        def do_GET(self):
            HITS.append((name,self.path))
            b=(b"<html><body><h1 id=t>tls-ok</h1><script src='http://127.0.0.1:%d/off.js'></script><img src='http://127.0.0.1:%d/blockme.png'></body></html>" % (OFF,OFF)) if name!="off" else b"window.__off=1"
            self.send_response(200); self.send_header("Content-Length",str(len(b))); self.send_header("Content-Type","text/html" if name!="off" else "application/javascript"); self.end_headers(); self.wfile.write(b)
    s=ThreadingHTTPServer(("127.0.0.1",0),H)
    if tls:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("c.pem","k.pem"); s.socket=ctx.wrap_socket(s.socket,server_side=True)
    threading.Thread(target=s.serve_forever,daemon=True).start(); return s.server_address[1]
OFF=mk("off"); T=mk("target"); TLS=mk("tls",True)
async def main(dport, mode):
    url = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{dport}/json/version").read())["webSocketDebuggerUrl"] if mode=="session" else [t for t in json.loads(urllib.request.urlopen(f"http://127.0.0.1:{dport}/json/list").read()) if t["type"]=="page"][0]["webSocketDebuggerUrl"]
    async with websockets.connect(url,max_size=None) as ws:
        n=0; sid=None
        async def call(m,p=None,t=8):
            nonlocal n; n+=1; f={"id":n,"method":m,"params":p or {}}
            if sid: f["sessionId"]=sid
            await ws.send(json.dumps(f)); end=time.time()+t
            while time.time()<end:
                try: v=json.loads(await asyncio.wait_for(ws.recv(),end-time.time()))
                except asyncio.TimeoutError: break
                if v.get("id")==n: return v
            return {"error":{"message":"timeout"}}
        if mode=="session":
            t=await call("Target.createTarget",{"url":"about:blank"}); a=await call("Target.attachToTarget",{"targetId":t["result"]["targetId"],"flatten":True}); sid=a["result"]["sessionId"]
        await call("Page.enable"); await call("Network.enable")
        r=await call("Network.setBlockedURLs",{"urls":[f"*127.0.0.1:{OFF}*"]})
        out={"setBlockedURLs_accepted":"error" not in r}
        await call("Page.navigate",{"url":f"http://127.0.0.1:{T}/"}); await asyncio.sleep(2)
        out["off_target_hits_despite_block"]=[h for h in HITS if h[0]=="off"]
        r=await call("Page.navigate",{"url":f"https://127.0.0.1:{TLS}/"}); await asyncio.sleep(2)
        e=await call("Runtime.evaluate",{"expression":"document.getElementById('t')?document.getElementById('t').textContent:'NO-DOM'","returnByValue":True})
        out["self_signed_https"]=e.get("result",{}).get("result",{}).get("value", e.get("error")); out["nav_err"]=r.get("result",{}).get("errorText") or r.get("error")
        print(json.dumps(out))
asyncio.run(main(int(sys.argv[1]),sys.argv[2]))
