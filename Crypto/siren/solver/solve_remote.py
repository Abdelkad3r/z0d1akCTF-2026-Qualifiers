#!/usr/bin/env python3
"""z0d1akCTF 2026 Qualifiers - Crypto - "siren"  --  exploit

ECDSA (secp256k1) with a biased nonce: each nonce's top PITCH_BITS (=10) bits are
public_pitch(msg) = MSBs of sha256(song_id + ":" + msg), fully computable by us.
That is a Hidden Number Problem with a 10-bit-per-signature leak. Collecting ~30+
signatures and running an LLL lattice attack recovers the private key D, after
which we forge a valid signature for the forbidden message and unlock the flag.

Usage:  DYLD_LIBRARY_PATH=/usr/local/opt/expat/lib PYTHONPATH=./libs \
        python3.13 solve_remote.py <host> [port] [nsigs]
"""
import socket, ssl, json, sys, time, os
import ec, attack as A
N=ec.N
HOST=sys.argv[1] if len(sys.argv)>1 else "siren-64d7f29be839.chals.z0d1ak.org"
PORT=int(sys.argv[2]) if len(sys.argv)>2 else 1337
NSIGS=int(sys.argv[3]) if len(sys.argv)>3 else 45

def connect(timeout=30):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    last=None
    for _ in range(5):
        try:
            raw=socket.create_connection((HOST,PORT),timeout=timeout)
            s=ctx.wrap_socket(raw, server_hostname=HOST); s.settimeout(timeout)
            return s, s.makefile('rwb', buffering=0)
        except Exception as e:
            last=e; time.sleep(1)
    raise last

def send(f,obj): f.write((json.dumps(obj)+"\n").encode())
def recv(f):
    while True:
        line=f.readline()
        if line==b"": raise EOFError("closed")
        line=line.strip()
        if line: return json.loads(line.decode())
def pubkey(f):
    send(f,{"cmd":"pubkey"}); pk=recv(f)
    return (int(pk["Qx"],16),int(pk["Qy"],16)), pk["song_id"], pk["priv_msg"]
def forge(D, priv_msg):
    z=A.msg_hash(priv_msg)
    while True:
        k=int.from_bytes(os.urandom(32),"big")%(N-1)+1
        R=ec.mul(k); r=R[0]%N
        if r==0: continue
        s=(pow(k,-1,N)*(z+r*D))%N
        if s: return r,s

def main():
    s,f=connect()
    print("[*]",recv(f).get("banner"))
    Q,song_id,priv_msg=pubkey(f)
    print("[*] song_id=%s priv_msg=%r"%(song_id,priv_msg))
    msgs=["verse-%d-%s"%(i,os.urandom(3).hex()) for i in range(NSIGS)]
    for m in msgs: send(f,{"cmd":"sign","msg":m})
    sigs=[]
    for m in msgs:
        r=recv(f)
        if "r" in r: sigs.append((m,int(r["r"],16),int(r["s"],16)))
    print("[*] collected %d signatures"%len(sigs))
    t0=time.time(); D=A.recover_D(sigs,song_id,Q)
    print("[*] key recovery: %.1fs -> %s"%(time.time()-t0,"OK" if D else "FAILED"))
    if not D: print("[!] increase nsigs and retry"); return
    assert ec.mul(D)==Q
    print("[+] D = %x"%D)
    r,ssig=forge(D,priv_msg)
    # try unlock on the same connection first
    try:
        send(f,{"cmd":"unlock","r":hex(r),"s":hex(ssig)})
        print("[+] unlock:", recv(f)); return
    except Exception as e:
        print("[*] same-conn unlock failed (%s); reconnecting (D is instance-global)"%e)
    s2,f2=connect(); recv(f2)
    Q2,sid2,pm2=pubkey(f2); assert Q2==Q and sid2==song_id
    r,ssig=forge(D,pm2)
    send(f2,{"cmd":"unlock","r":hex(r),"s":hex(ssig)})
    print("[+] unlock:", recv(f2))

if __name__=="__main__": main()
