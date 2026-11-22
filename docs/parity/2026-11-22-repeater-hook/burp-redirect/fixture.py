from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import json,pathlib
ROOT=pathlib.Path('/downloads/burp-comparison/redirect')
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  row={'path':self.path,'probe_values':self.headers.get_all('X-Parity-Probe') or [],'headers':list(self.headers.items())}
  row['probe_count']=len(row['probe_values'])
  with (ROOT/'origin.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  if self.path=='/start':
   self.send_response(302);self.send_header('Location','/finish');self.send_header('Content-Length','0');self.end_headers()
  else:
   body=json.dumps(row,indent=2).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*a):pass
ThreadingHTTPServer(('127.0.0.1',18767),Handler).serve_forever()
