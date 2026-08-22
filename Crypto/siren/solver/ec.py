# Pure-python secp256k1
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv(a, m): return pow(a % m, -1, m)

def add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1,y1 = Pt; x2,y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if Pt == Qt:
        l = (3*x1*x1 + A) * inv(2*y1, P) % P
    else:
        l = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (l*l - x1 - x2) % P
    y3 = (l*(x1 - x3) - y1) % P
    return (x3, y3)

def mul(k, Pt=(Gx,Gy)):
    k %= N
    R = None
    while k:
        if k & 1: R = add(R, Pt)
        Pt = add(Pt, Pt)
        k >>= 1
    return R
G = (Gx, Gy)
