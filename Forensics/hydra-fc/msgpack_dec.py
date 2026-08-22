import struct
class R:
    def __init__(self,b): self.b=b; self.i=0
    def u(self,n):
        v=self.b[self.i:self.i+n]; self.i+=n; return v
    def byte(self):
        v=self.b[self.i]; self.i+=1; return v
def dec(r):
    c=r.byte()
    if c<0x80: return c                      # positive fixint
    if c>=0xe0: return c-256                  # negative fixint
    if 0x80<=c<=0x8f: return {dec(r):dec(r) for _ in range(c&0x0f)}   # fixmap
    if 0x90<=c<=0x9f: return [dec(r) for _ in range(c&0x0f)]          # fixarray
    if 0xa0<=c<=0xbf: return r.u(c&0x1f).decode('utf-8','replace')    # fixstr
    if c==0xc0: return None
    if c==0xc2: return False
    if c==0xc3: return True
    if c==0xcc: return r.byte()
    if c==0xcd: return struct.unpack('>H',r.u(2))[0]
    if c==0xce: return struct.unpack('>I',r.u(4))[0]
    if c==0xcf: return struct.unpack('>Q',r.u(8))[0]
    if c==0xd0: return struct.unpack('>b',r.u(1))[0]
    if c==0xd1: return struct.unpack('>h',r.u(2))[0]
    if c==0xd2: return struct.unpack('>i',r.u(4))[0]
    if c==0xd3: return struct.unpack('>q',r.u(8))[0]
    if c==0xca: return struct.unpack('>f',r.u(4))[0]
    if c==0xcb: return struct.unpack('>d',r.u(8))[0]
    if c==0xd9: n=r.byte(); return r.u(n).decode('utf-8','replace')
    if c==0xda: n=struct.unpack('>H',r.u(2))[0]; return r.u(n).decode('utf-8','replace')
    if c==0xdb: n=struct.unpack('>I',r.u(4))[0]; return r.u(n).decode('utf-8','replace')
    if c==0xdc: n=struct.unpack('>H',r.u(2))[0]; return [dec(r) for _ in range(n)]
    if c==0xdd: n=struct.unpack('>I',r.u(4))[0]; return [dec(r) for _ in range(n)]
    if c==0xde: n=struct.unpack('>H',r.u(2))[0]; return {dec(r):dec(r) for _ in range(n)}
    if c==0xdf: n=struct.unpack('>I',r.u(4))[0]; return {dec(r):dec(r) for _ in range(n)}
    raise ValueError("unknown msgpack byte 0x%02x at %d"%(c,r.i-1))
def loads(b): return dec(R(b))
