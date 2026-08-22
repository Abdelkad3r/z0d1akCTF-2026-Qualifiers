import struct
def read_varint(b,i):
    shift=0; val=0
    while True:
        x=b[i]; i+=1
        val|=(x&0x7f)<<shift
        if not (x&0x80): break
        shift+=7
    return val,i
def parse_fields(b):
    """Generic protobuf -> dict field_num -> list of values (varint as int, len-delim as bytes)."""
    i=0; out={}
    while i<len(b):
        tag,i=read_varint(b,i)
        fn=tag>>3; wt=tag&7
        if wt==0:
            v,i=read_varint(b,i)
        elif wt==2:
            ln,i=read_varint(b,i); v=b[i:i+ln]; i+=ln
        elif wt==1:
            v=b[i:i+8]; i+=8
        elif wt==5:
            v=b[i:i+4]; i+=4
        else:
            raise ValueError("wt %d"%wt)
        out.setdefault(fn,[]).append(v)
    return out
def entries(path):
    b=open(path,'rb').read()
    magic1=b[0:4]; magic2=b[4:8]; i=8
    ents=[]
    while i<len(b):
        if i+4>len(b): break
        size=struct.unpack('<I',b[i:i+4])[0]; i+=4
        data=b[i:i+size]; i+=size
        ents.append(data)
    return magic1,magic2,ents
