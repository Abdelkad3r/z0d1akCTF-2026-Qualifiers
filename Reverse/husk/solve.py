import struct
import os
HERE=os.path.dirname(os.path.abspath(__file__))
_p=next(p for p in ["husk", os.path.join(HERE,"challenge","husk"), os.path.join(HERE,"husk")] if os.path.exists(p))
d=open(_p,"rb").read()
N=0x29  # 41

def rol8(x,r): r&=7; return ((x<<r)|(x>>(8-r)))&0xff
def ror8(x,r): r&=7; return ((x>>r)|(x<<(8-r)))&0xff

# ---- constants from rodata ----
table1=d[0x206c:0x206c+41]           # 41 bytes
table2=d[0x20a0:0x20a0+16]           # 16 bytes

# CONST_B[i] = table1[(0x11*i)%41] ^ table2[i%16]
CONST_B=bytes(table1[(0x11*i)%41]^table2[i%16] for i in range(N))

# ---- env key (clean run) ----
d0=0^0x1337c0de   # ptrace()=0
d1=0^0xb16b00b5   # TracerPid=0
d2=0^0xfeedface   # timing ok
d3=0^0xcafebabe   # no LD_PRELOAD
env_key=struct.pack("<IIII",d0,d1,d2,d3)   # 16 bytes

# ---- RC4 keystream with env_key ----
def rc4_ks(key,n):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    out=[]; i=j=0
    for _ in range(n):
        i=(i+1)&0xff; j=(j+S[i])&0xff
        S[i],S[j]=S[j],S[i]
        out.append(S[(S[i]+S[j])&0xff])
    return bytes(out)

EXPECTED=bytes(a^b for a,b in zip(rc4_ks(env_key,N),CONST_B))
print("env_key   :",env_key.hex())
print("CONST_B   :",CONST_B.hex())
print("EXPECTED  :",EXPECTED.hex())

# ---- LCG buffer ----
def lcg_buf(n):
    st=0x1234abcd; out=[]
    for _ in range(n):
        st=(st*0x41c64e6d+0x3039)&0xffffffff
        out.append((st>>24)&0xff)
    return bytes(out)
LCG=lcg_buf(N)

# ---- one forward round on 41-byte buffer ----
def fwd_round(buf, rnd):
    r9=0x3d*rnd; r11=2*rnd; r13=3*rnd; r10=(0x13+0x47*rnd)&0xffffffff; r14=(0x15+0x2b*rnd)&0xffffffff
    # loop1
    out1=[0]*N
    state=(r9^0xa5)&0xff
    for i in range(N):
        v=(buf[i]+0x1d*i+r10)&0xff
        c1=((rnd+i)%7)+1
        c2=((r11+i)%7)+1
        v=rol8(v,c1)
        state=rol8(state,c2)^v
        state&=0xff
        out1[i]=state
    # loop2 (rdi from 0x28 down to 0)
    out2=[0]*N
    al=((13*r13)^0x5c)&0xff
    k=0
    for rdi in range(0x28,-1,-1):
        c1=((r13+rdi)%7)+1
        al=rol8(al,c1)
        al^=out1[rdi]
        ebp=(r14 - 0x11*k)&0xff
        al=(al+ebp)&0xff
        r8=(rnd+0x78-3*k)
        c2=((r8%7)+1)
        al=rol8(al,c2)
        out2[rdi]=al
        k+=1
    # permutation: out3[(5*rnd+7*k)%41]=out2[k]
    out3=[0]*N
    for k in range(N):
        out3[(5*rnd+7*k)%41]=out2[k]
    return bytes(out3)

def inv_round(buf, rnd):
    r9=0x3d*rnd; r11=2*rnd; r13=3*rnd; r10=(0x13+0x47*rnd)&0xffffffff; r14=(0x15+0x2b*rnd)&0xffffffff
    # un-permute
    out2=[0]*N
    for k in range(N):
        out2[k]=buf[(5*rnd+7*k)%41]
    # un-loop2
    out1=[0]*N
    al_prev=((13*r13)^0x5c)&0xff
    k=0
    for rdi in range(0x28,-1,-1):
        c1=((r13+rdi)%7)+1
        ebp=(r14 - 0x11*k)&0xff
        r8=(rnd+0x78-3*k); c2=((r8%7)+1)
        al4=out2[rdi]
        al3=ror8(al4,c2)
        al2=(al3-ebp)&0xff
        al1=rol8(al_prev,c1)
        out1[rdi]=al2^al1
        al_prev=al4
        k+=1
    # un-loop1
    inp=[0]*N
    state=(r9^0xa5)&0xff
    for i in range(N):
        s=state if i==0 else out1[i-1]
        c1=((rnd+i)%7)+1
        c2=((r11+i)%7)+1
        tmp=out1[i]^rol8(s,c2)
        y=ror8(tmp,c1)
        inp[i]=(y-0x1d*i-r10)&0xff
    return bytes(inp)

# invert F: rounds 6..0
buf=EXPECTED
for rnd in range(5,-1,-1):
    buf=inv_round(buf,rnd)
input_x=buf
flag=bytes(a^b for a,b in zip(input_x,LCG))
print("\nrecovered flag:",flag)

# verify forward
chk=bytes(a^b for a,b in zip(flag,LCG))
for rnd in range(6):
    chk=fwd_round(chk,rnd)
print("forward(flag)==EXPECTED:",chk==EXPECTED)
