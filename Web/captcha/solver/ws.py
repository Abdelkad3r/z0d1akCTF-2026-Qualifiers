import socket, ssl, base64, os, threading, struct, time

class WS:
    def __init__(self, host, path, cookie=None, origin=None, port=443):
        self.host=host; self.path=path; self.cookie=cookie
        self.origin=origin or f"https://{host}"; self.port=port
        self.sock=None; self.alive=False; self.reader=None
    def connect(self, timeout=8):
        raw=socket.create_connection((self.host,self.port),timeout=timeout)
        ctx=ssl.create_default_context()
        self.sock=ctx.wrap_socket(raw, server_hostname=self.host)
        key=base64.b64encode(os.urandom(16)).decode()
        req=(f"GET {self.path} HTTP/1.1\r\n"
             f"Host: {self.host}\r\n"
             f"Upgrade: websocket\r\n"
             f"Connection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\n"
             f"Sec-WebSocket-Version: 13\r\n"
             f"Origin: {self.origin}\r\n")
        if self.cookie: req+=f"Cookie: {self.cookie}\r\n"
        req+="\r\n"
        self.sock.sendall(req.encode())
        # read handshake response headers
        buf=b""
        while b"\r\n\r\n" not in buf:
            ch=self.sock.recv(4096)
            if not ch: raise RuntimeError("ws handshake closed")
            buf+=ch
        head=buf.split(b"\r\n\r\n",1)[0]
        if b"101" not in head.split(b"\r\n",1)[0]:
            raise RuntimeError("ws handshake failed: "+head.decode(errors='replace')[:200])
        self.leftover=buf.split(b"\r\n\r\n",1)[1]
        self.alive=True
        self.reader=threading.Thread(target=self._read_loop,daemon=True)
        self.reader.start()
        return self
    def _recv_exact(self,n):
        data=self.leftover[:n]; self.leftover=self.leftover[n:]
        while len(data)<n:
            ch=self.sock.recv(n-len(data))
            if not ch: raise RuntimeError("closed")
            data+=ch
        return data
    def _read_loop(self):
        try:
            while self.alive:
                b0=self._recv_exact(1)[0]; b1=self._recv_exact(1)[0]
                opcode=b0&0x0f; masked=b1&0x80; ln=b1&0x7f
                if ln==126: ln=struct.unpack(">H",self._recv_exact(2))[0]
                elif ln==127: ln=struct.unpack(">Q",self._recv_exact(8))[0]
                mask=self._recv_exact(4) if masked else b""
                payload=self._recv_exact(ln) if ln else b""
                if opcode==0x9:  # ping -> pong
                    self._send(0xA,payload)
                elif opcode==0x8:  # close
                    self.alive=False; break
        except Exception:
            self.alive=False
    def _send(self,opcode,payload=b""):
        b0=0x80|opcode
        ln=len(payload); hdr=bytearray([b0])
        if ln<126: hdr.append(0x80|ln)
        elif ln<65536: hdr.append(0x80|126); hdr+=struct.pack(">H",ln)
        else: hdr.append(0x80|127); hdr+=struct.pack(">Q",ln)
        m=os.urandom(4); hdr+=m
        masked=bytes(payload[i]^m[i%4] for i in range(ln))
        try: self.sock.sendall(bytes(hdr)+masked)
        except Exception: self.alive=False
    def close(self):
        self.alive=False
        try: self.sock.close()
        except: pass

if __name__=='__main__':
    import http.cookiejar, urllib.request, json, uuid
    BASE="captcha-aa0eac22359e.chals.z0d1ak.org"
    cj=http.cookiejar.CookieJar()
    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    def call(m,p,b=None,h=None):
        d=json.dumps(b).encode() if b is not None else None
        hd={'Content-Type':'application/json'} if b is not None else {}
        if h: hd.update(h)
        r=op.open(urllib.request.Request("https://"+BASE+p,data=d,headers=hd,method=m),timeout=15)
        return r.status, json.loads(r.read().decode() or 'null')
    t=time.time(); call('GET','/api/state'); print('RTT state %.0fms'%((time.time()-t)*1000))
    call('POST','/api/session/restart',{})
    st,d=call('POST','/api/check/start',{'client_id':str(uuid.uuid4())})
    print('reg',st,d['challenge'],'chan',d['channel_id'])
    cookie="; ".join(f"{c.name}={c.value}" for c in cj)
    ws=WS(BASE,f"/api/check/live?channel={d['channel_id']}",cookie=cookie)
    t=time.time(); ws.connect(); print('WS connected %.0fms alive=%s'%((time.time()-t)*1000,ws.alive))
    time.sleep(1.2)
    st,r=call('POST',f"/api/checks/{d['check_id']}/verify",{'transcript':{'placements':[]}},{'X-Check-Channel':d['channel_id']})
    print('verify with WS open ->',st,r if st!=200 else 'OK proof')
    ws.close()
