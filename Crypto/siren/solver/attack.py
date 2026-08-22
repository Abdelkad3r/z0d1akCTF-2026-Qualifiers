"""Hidden Number Problem recovery of the siren ECDSA private key.

Each signature leaks the top PITCH_BITS (=10) bits of its nonce, because
    k = (public_pitch(msg) << SUFFIX_BITS) | random(SUFFIX_BITS)
and public_pitch(msg) = MSBs of sha256(song_id + ":" + msg) is public.

For signature i:  k_i = s_i^-1 (z_i + r_i D)  (mod N),  with the top bits of k_i
known, so e_i = k_i - a_i is small (0 <= e_i < 2^SUFFIX_BITS), where
a_i = public_pitch << SUFFIX_BITS. Writing t_i = r_i s_i^-1 and u_i = z_i s_i^-1,

    t_i * D + (u_i - a_i)  ==  e_i   (mod N),   |e_i| bounded by 2^246.

Centering e_i about B/2 and building the standard HNP lattice (m N-diagonal
rows + a D-marker row + a target row, with the D column weighted by K = 2^10 so
D's contribution matches the nonce scale), LLL yields a short vector whose
coordinates reveal the centered nonces. From any recovered nonce k_i,
    D = (s_i k_i - z_i) r_i^-1  (mod N),
and we accept the candidate whose D satisfies D*G == Q.
"""
import hashlib, ec
from lll import lll
N=ec.N
PITCH_BITS=10
SUFFIX_BITS=256-PITCH_BITS
BND=1<<SUFFIX_BITS
B2=BND//2
K=1<<PITCH_BITS   # weight so that D * 1  ~  K * e'_i  (balances the D-marker column)

def msg_hash(msg): return int.from_bytes(hashlib.sha256(msg.encode()).digest(),"big")%N
def public_pitch(song_id,msg):
    h=int.from_bytes(hashlib.sha256((song_id+":"+msg).encode()).digest(),"big")
    return h>>(256-PITCH_BITS)

def recover_D(sigs, song_id, Q):
    m=len(sigs)
    t=[];cp=[];a=[];z=[];rr=[];ss=[]
    for (msg,r,s) in sigs:
        zz=msg_hash(msg); w=pow(s,-1,N)
        t.append((r*w)%N)
        ai=public_pitch(song_id,msg)<<SUFFIX_BITS
        ci=((zz*w)%N - ai)%N
        cp.append((ci-B2)%N); a.append(ai); z.append(zz); rr.append(r); ss.append(s)
    M=[[0]*(m+2) for _ in range(m+2)]
    for i in range(m): M[i][i]=N*K
    for i in range(m): M[m][i]=t[i]*K
    M[m][m]=1
    for i in range(m): M[m+1][i]=cp[i]*K
    M[m+1][m+1]=B2*K
    R=lll(M)
    def ok(D): return 1<=D<N and ec.mul(D)==Q
    def D_from_nonce(e,i):
        k_i=a[i]+e+B2
        if 1<=k_i<N:
            return ((ss[i]*k_i - z[i])*pow(rr[i],-1,N))%N
        return None
    cands=set()
    for row in R:
        cands.add(row[m]%N); cands.add((-row[m])%N)
        for i in range(m):
            if row[i]%K==0:
                ep=row[i]//K
                for e in (ep,-ep):
                    D=D_from_nonce(e,i)
                    if D is not None: cands.add(D)
    for D in cands:
        if ok(D): return D
    return None
