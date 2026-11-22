import socket,base64,os,struct,json,pathlib
root=pathlib.Path('/downloads/burp-comparison/followup')
for port in [18080,18081]:
 out={'proxy_port':port,'payload':'parity-ws'}
 try:
  s=socket.create_connection(('127.0.0.1',port),timeout=5)
  s.settimeout(5)
  request=('GET http://127.0.0.1:18766/ws HTTP/1.1\r\nHost: 127.0.0.1:18766\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+base64.b64encode(b'parity-probe-key!').decode()+'\r\n\r\n')
  s.sendall(request.encode()); response=b''
  while b'\r\n\r\n' not in response: response+=s.recv(4096)
  out['handshake']=response.decode(errors='replace')
  p=out['payload'].encode(); mask=b'ABCD'
  s.sendall(bytes([0x81,0x80|len(p)])+mask+bytes(c^mask[i%4] for i,c in enumerate(p)))
  data=s.recv(1024);out['frame_hex']=data.hex();out['echo']=data[2:].decode(errors='replace')
  s.sendall(b'\x88\x80ABCD');s.close()
 except Exception as e: out['error']=str(e)
 (root/f'ws-{port}.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(out))
