import struct
data=open("relay","rb").read()
PCLN_VA=0x4ee2d0; PCLN_OFF=0xee2d0; PCLN_SIZE=0xb2d96
p=data[PCLN_OFF:PCLN_OFF+PCLN_SIZE]
magic=struct.unpack("<I",p[0:4])[0]
print("pcln magic %08x"%magic)
ptrsize=p[7]
def uptr(off): 
    return struct.unpack("<Q",p[off:off+8])[0] if ptrsize==8 else struct.unpack("<I",p[off:off+4])[0]
# pcHeader layout (go1.18+): magic(4),pad(2),minLC(1),ptrSize(1),nfunc,nfiles,textStart,funcnameOff,cuOff,filetabOff,pctabOff,pclnOff
nfunc=uptr(8)
nfiles=uptr(8+ptrsize)
textStart=uptr(8+2*ptrsize)
funcnameOff=uptr(8+3*ptrsize)
cuOff=uptr(8+4*ptrsize)
filetabOff=uptr(8+5*ptrsize)
pctabOff=uptr(8+6*ptrsize)
pclnOff=uptr(8+7*ptrsize)
print("nfunc",nfunc,"textStart %x"%textStart,"funcnameOff %x"%funcnameOff,"pclnOff %x"%pclnOff)
functab=pclnOff
# each functab entry: (uint32 entryoff, uint32 funcoff)  -- go1.18+ uses uint32 when possible
def u32(off): return struct.unpack("<I",p[off:off+4])[0]
funcs=[]
for i in range(nfunc):
    entryoff=u32(functab+i*8)
    funcoff=u32(functab+i*8+4)
    fstart=pclnOff  # _func structs are at pclnOff + funcoff
    fd=pclnOff+funcoff
    nameoff=u32(fd+4)  # _func: entryOff(4), nameOff(4)
    # name string at funcnameOff+nameoff
    s=funcnameOff+nameoff
    e=p.index(b'\x00',s)
    name=p[s:e].decode('latin1')
    va=textStart+entryoff
    funcs.append((va,name))
funcs.sort()
import sys
targets=["main.deriveIncidentKey","main.xorStream","main.queueDigest","main.marshalQueue","main.selfTest","main.main","main.RelayState.MarshalBinary"]
byname={n:va for va,n in funcs}
# find next va for size
va_sorted=[va for va,_ in funcs]
for t in targets:
    matches=[(va,n) for va,n in funcs if n==t or n.endswith(t)]
    for va,n in matches:
        idx=va_sorted.index(va)
        nextva=va_sorted[idx+1] if idx+1<len(va_sorted) else va+0x400
        print(f"{n}  va=0x{va:x}  size=0x{nextva-va:x}")
open("funcs.txt","w").write("\n".join("0x%x %s"%(va,n) for va,n in funcs))
print("total funcs:",len(funcs),"-> funcs.txt")
