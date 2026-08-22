# Minimal pure-python AES-256 + GCM (decrypt & verify)
sbox=[]
def _init_sbox():
    p=1;q=1;sb=[0]*256
    # compute sbox via standard algorithm
    inv=[0]*256
    # multiplicative inverse in GF(2^8)
    def gmul(a,b):
        r=0
        for _ in range(8):
            if b&1: r^=a
            hi=a&0x80; a=(a<<1)&0xff
            if hi: a^=0x1b
            b>>=1
        return r
    # build inverse table
    invt=[0]*256
    for a in range(1,256):
        for b in range(1,256):
            if gmul(a,b)==1:
                invt[a]=b; break
    def rotl8(x,s): return ((x<<s)|(x>>(8-s)))&0xff
    sb[0]=0x63
    for a in range(1,256):
        x=invt[a]
        s=x^rotl8(x,1)^rotl8(x,2)^rotl8(x,3)^rotl8(x,4)^0x63
        sb[a]=s
    return sb
sbox=_init_sbox()
Rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]

def xtime(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)&0xff
def gmul(a,b):
    r=0
    for _ in range(8):
        if b&1: r^=a
        hi=a&0x80; a=(a<<1)&0xff
        if hi: a^=0x1b
        b>>=1
    return r

def key_expansion(key):
    Nk=len(key)//4; Nr=Nk+6
    w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,4*(Nr+1)):
        temp=list(w[i-1])
        if i%Nk==0:
            temp=temp[1:]+temp[:1]
            temp=[sbox[b] for b in temp]
            temp[0]^=Rcon[i//Nk-1]
        elif Nk>6 and i%Nk==4:
            temp=[sbox[b] for b in temp]
        w.append([w[i-Nk][j]^temp[j] for j in range(4)])
    return w,Nr

def add_round_key(state,w,rnd):
    for c in range(4):
        for r in range(4):
            state[r][c]^=w[rnd*4+c][r]

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c]=sbox[state[r][c]]

def shift_rows(state):
    for r in range(1,4):
        state[r]=state[r][r:]+state[r][:r]

def mix_columns(state):
    for c in range(4):
        a=[state[r][c] for r in range(4)]
        state[0][c]=gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3]
        state[1][c]=a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3]
        state[2][c]=a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3)
        state[3][c]=gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2)

def aes_encrypt_block(block,w,Nr):
    state=[[block[r+4*c] for c in range(4)] for r in range(4)]
    add_round_key(state,w,0)
    for rnd in range(1,Nr):
        sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state,w,rnd)
    sub_bytes(state); shift_rows(state); add_round_key(state,w,Nr)
    return bytes(state[r][c] for c in range(4) for r in range(4))

class AES:
    def __init__(self,key):
        self.w,self.Nr=key_expansion(key)
    def encrypt(self,block):
        return aes_encrypt_block(block,self.w,self.Nr)

# GF(2^128) for GHASH
def gf_mul(x,y):
    R=0xe1<<120; z=0; v=y
    for i in range(128):
        if (x>>(127-i))&1: z^=v
        v=(v>>1)^R if v&1 else v>>1
    return z
def b2i(b): return int.from_bytes(b,'big')
def i2b(x): return x.to_bytes(16,'big')

def ghash(H,data):
    y=0
    for i in range(0,len(data),16):
        blk=data[i:i+16]
        blk=blk+b'\x00'*(16-len(blk))
        y=gf_mul(y^b2i(blk),H)
    return y

def gcm_decrypt(key,nonce,ct,tag,aad):
    aes=AES(key)
    H=b2i(aes.encrypt(b'\x00'*16))
    if len(nonce)==12:
        J0=nonce+b'\x00\x00\x00\x01'
    else:
        raise ValueError("only 96-bit nonce")
    # GHASH: aad padded, ct padded, then lengths
    def pad16(d): return d+b'\x00'*((-len(d))%16)
    lenblock=(len(aad)*8).to_bytes(8,'big')+(len(ct)*8).to_bytes(8,'big')
    S=ghash(H, pad16(aad)+pad16(ct)+lenblock)
    EJ0=b2i(aes.encrypt(J0))
    tag_calc=i2b(S^EJ0)
    # CTR decrypt
    def inc32(b):
        pre=b[:12]; ctr=int.from_bytes(b[12:],'big')
        return pre+((ctr+1)&0xffffffff).to_bytes(4,'big')
    out=b''; ctr=inc32(J0)
    for i in range(0,len(ct),16):
        ks=aes.encrypt(ctr)
        blk=ct[i:i+16]
        out+=bytes(a^b for a,b in zip(blk,ks))
        ctr=inc32(ctr)
    return out, (tag_calc==tag)
