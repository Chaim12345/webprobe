#!/usr/bin/env python3
"""Capability probe: does a CDP browser support what WebProbe's crawler and
DOM probe need? Usage: probe.py <devtools-port> <label>"""
import asyncio, base64, json, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import websockets

HITS = []

PAGE = b"""<html><head><link rel='stylesheet' href='/s.css'></head><body>
<a href='/next?a=1'>next</a><form action='/login' method='post'><input name='u'></form>
<div id='o'></div>
<script src='/app.js'></script>
<script>
var m=/__proto__\\[([^\\]]+)\\]=([^&#]*)/.exec(location.hash);if(m)Object.prototype[m[1]]=m[2];
document.getElementById('o').innerHTML = decodeURIComponent(location.hash.slice(1));
fetch('/api?x=1').then(r=>r.text()).then(t=>{window.__api=t});
var x=new XMLHttpRequest();x.open('POST','/xhr');x.send('k=v');
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab", "1")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        HITS.append(("GET", self.path, dict(self.headers)))
        if self.path.startswith("/app.js"):
            self._send(b"window.__appjs=1;", "application/javascript")
        elif self.path.startswith("/s.css"):
            self._send(b"body{color:red}", "text/css")
        elif self.path.startswith("/api"):
            self._send(b'{"ok":true}', "application/json")
        else:
            self._send(PAGE)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        HITS.append(("POST", self.path, self.rfile.read(n).decode()))
        self._send(b"posted", "text/plain")


class Cdp:
    def __init__(self, ws):
        self.ws, self.n, self.events, self.sid = ws, 0, [], None

    def frame(self, mid, method, params):
        m = {"id": mid, "method": method, "params": params or {}}
        if self.sid:
            m["sessionId"] = self.sid
        return json.dumps(m)

    async def call(self, method, params=None, timeout=8, on_event=None):
        self.n += 1
        mid = self.n
        await self.ws.send(self.frame(mid, method, params))
        end = time.time() + timeout
        while time.time() < end:
            try:
                raw = await asyncio.wait_for(self.ws.recv(), end - time.time())
            except asyncio.TimeoutError:
                break
            v = json.loads(raw)
            if v.get("id") == mid:
                return v
            self.events.append(v)
            if on_event:
                await on_event(v)
        return {"error": {"message": "timeout"}}

    async def pump(self, secs, on_event=None):
        end = time.time() + secs
        while time.time() < end:
            try:
                raw = await asyncio.wait_for(self.ws.recv(), max(0.01, end - time.time()))
            except asyncio.TimeoutError:
                break
            v = json.loads(raw)
            self.events.append(v)
            if on_event:
                await on_event(v)


def ok(r):
    return "error" not in r


async def main(dport, label):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    out = {"label": label}

    lst = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{dport}/json/list", timeout=5).read())
    pages = [t for t in lst if t.get("type") == "page"]
    out["json_list_page_target"] = bool(pages)
    if not pages:
        ver = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{dport}/json/version", timeout=5).read())
        out["json_version"] = ver
        print(json.dumps(out, indent=1))
        return
    mode = sys.argv[3] if len(sys.argv) > 3 else "page"
    out["mode"] = mode
    url = pages[0]["webSocketDebuggerUrl"] if mode == "page" else json.loads(urllib.request.urlopen(f"http://127.0.0.1:{dport}/json/version", timeout=5).read())["webSocketDebuggerUrl"]
    async with websockets.connect(url, max_size=None) as ws:
        c = Cdp(ws)
        if mode != "page":
            t = await c.call("Target.createTarget", {"url": "about:blank"})
            a = await c.call("Target.attachToTarget", {"targetId": t["result"]["targetId"], "flatten": True})
            c.sid = a["result"]["sessionId"]
        for m in ["Page.enable", "Network.enable"]:
            out[m] = ok(await c.call(m))
        r = await c.call("Network.setBypassServiceWorker", {"bypass": True})
        out["Network.setBypassServiceWorker"] = ok(r) or r["error"]["message"]
        r = await c.call("Page.addScriptToEvaluateOnNewDocument", {"source": "window.__hook = (window.__hook||0)+1; window.__sinks=[]; var d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML'); Object.defineProperty(Element.prototype,'innerHTML',{set:function(v){window.__sinks.push(String(v)); return d.set.call(this,v)},get:d.get});"})
        out["Page.addScriptToEvaluateOnNewDocument"] = ok(r) or r["error"]["message"]

        # --- crawl-style navigation with Network events
        c.events.clear()
        HITS.clear()
        r = await c.call("Page.navigate", {"url": f"{base}/?q=1#<img src=x onerror=1>&__proto__[tokh]=tokh"})
        out["Page.navigate"] = ok(r) or r["error"]["message"]
        await c.pump(3)
        methods = {}
        for e in c.events:
            if "method" in e:
                methods[e["method"]] = methods.get(e["method"], 0) + 1
        out["events_seen"] = methods
        out["lab_hits_plain_nav"] = [(h[0], h[1]) for h in HITS]
        sent = [e["params"] for e in c.events if e.get("method") == "Network.requestWillBeSent"]
        out["requestWillBeSent_urls"] = [(p["request"]["method"], p["request"]["url"].replace(base, ""), bool(p["request"].get("postData"))) for p in sent]
        body_ok = None
        for p in sent:
            if p["request"]["url"].startswith(base + "/?q=1"):
                rb = await c.call("Network.getResponseBody", {"requestId": p["requestId"]})
                body_ok = ok(rb) and ("__proto__" in (base64.b64decode(rb["result"]["body"]).decode() if rb["result"].get("base64Encoded") else rb["result"]["body"]))
        out["Network.getResponseBody(document)"] = body_ok
        ev = await c.call("Runtime.evaluate", {"expression": "JSON.stringify({hook:window.__hook,sinks:window.__sinks,polluted:({}).tokh,app:window.__appjs,api:window.__api,links:[...document.querySelectorAll('a')].map(a=>a.href),forms:[...document.forms].map(f=>f.action+' '+f.method)})", "returnByValue": True})
        out["Runtime.evaluate(page state)"] = json.loads(ev["result"]["result"]["value"]) if ok(ev) and "value" in ev.get("result", {}).get("result", {}) else ev

        # --- DOM-probe style: Fetch interception of EVERY request, fulfilled by the client
        paused = []

        async def on_event(v):
            if v.get("method") == "Fetch.requestPaused":
                p = v["params"]
                url = p["request"]["url"]
                paused.append((p.get("resourceType"), p["request"]["method"], url.replace(base, "")))
                c.n += 1
                if url.startswith(base + "/blocked"):
                    await c.ws.send(c.frame(c.n, "Fetch.failRequest", {"requestId": p["requestId"], "errorReason": "BlockedByClient"}))
                elif "/app.js" in url:
                    body = b"window.__appjs='fulfilled';"
                    await c.ws.send(c.frame(c.n, "Fetch.fulfillRequest", {"requestId": p["requestId"], "responseCode": 200, "responseHeaders": [{"name": "Content-Type", "value": "application/javascript"}], "body": base64.b64encode(body).decode()}))
                elif url.startswith(base + "/?"):
                    body = PAGE.replace(b"next</a>", b"FULFILLED</a>")
                    await c.ws.send(c.frame(c.n, "Fetch.fulfillRequest", {"requestId": p["requestId"], "responseCode": 200, "responseHeaders": [{"name": "Content-Type", "value": "text/html"}], "body": base64.b64encode(body).decode()}))
                else:
                    await c.ws.send(c.frame(c.n, "Fetch.failRequest", {"requestId": p["requestId"], "errorReason": "BlockedByClient"}))

        r = await c.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
        out["Fetch.enable"] = ok(r) or r["error"]["message"]
        r = await c.call("Network.setBlockedURLs", {"urls": ["*blockme*"]})
        out["Network.setBlockedURLs"] = ok(r) or r["error"]["message"]
        HITS.clear()
        c.events.clear()
        r = await c.call("Page.navigate", {"url": f"{base}/?probe=2#x&__proto__[tok2]=tok2"}, on_event=on_event)
        await c.pump(3, on_event)
        out["Fetch.requestPaused"] = paused
        out["lab_hits_during_interception (must be empty for fail-closed)"] = [(h[0], h[1]) for h in HITS]
        ev = await c.call("Runtime.evaluate", {"expression": "JSON.stringify({a:document.querySelector('a')&&document.querySelector('a').textContent,app:window.__appjs,polluted:({}).tok2,hook:window.__hook,sinks:(window.__sinks||[]).length})", "returnByValue": True}, on_event=on_event)
        out["Runtime.evaluate(after interception)"] = json.loads(ev["result"]["result"]["value"]) if ok(ev) and "value" in ev.get("result", {}).get("result", {}) else ev
    print(json.dumps(out, indent=1))


asyncio.run(main(int(sys.argv[1]), sys.argv[2]))
