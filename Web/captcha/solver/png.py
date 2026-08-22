import zlib, struct

def write_gray(path, w, h, data):
    raw = bytearray()
    for y in range(h):
        raw.append(0); raw += data[y*w:(y+1)*w]
    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 0, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    open(path, 'wb').write(png)

def read_gray(path):
    d = open(path,'rb').read()
    assert d[:8] == b'\x89PNG\r\n\x1a\n'
    off = 8; idat = b''; w=h=bd=ct=None
    while off < len(d):
        ln, = struct.unpack_from('>I', d, off); t = d[off+4:off+8]
        pay = d[off+8:off+8+ln]; off += 12+ln
        if t == b'IHDR': w,h,bd,ct,_,_,il = struct.unpack('>IIBBBBB', pay); assert il==0
        elif t == b'IDAT': idat += pay
    assert bd == 8 and ct == 0, (bd, ct)
    raw = zlib.decompress(idat)
    out = bytearray(w*h); prev = bytearray(w)
    p = 0
    for y in range(h):
        f = raw[p]; p += 1
        line = bytearray(raw[p:p+w]); p += w
        if f == 1:
            for x in range(1, w): line[x] = (line[x] + line[x-1]) & 255
        elif f == 2:
            for x in range(w): line[x] = (line[x] + prev[x]) & 255
        elif f == 3:
            for x in range(w):
                a = line[x-1] if x else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 255
        elif f == 4:
            for x in range(w):
                a = line[x-1] if x else 0
                b = prev[x]; c = prev[x-1] if x else 0
                pp = a+b-c; pa=abs(pp-a); pb=abs(pp-b); pc=abs(pp-c)
                pr = a if (pa<=pb and pa<=pc) else (b if pb<=pc else c)
                line[x] = (line[x] + pr) & 255
        out[y*w:(y+1)*w] = line; prev = line
    return w, h, bytes(out)
