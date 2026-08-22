#!/usr/bin/env python3
"""
Offline reproduction for Rewind Revenge - no network required.

Reads the captured seals (artifacts/seals.txt), recovers H^2 and the constant P,
validates the linear tag model on an independent seal, and reconstructs the exact
forged (ciphertext, tag) that unlocked the flag.

    $ python3 verify_offline.py
    [*] H2 = 5fcfbd26302585d1fd8541653cf3992d
    [*] P  = d517c7829dc6901b2fdc93bceedd8231
    [*] model validated on the held-out seal: True
    [+] forged ciphertext = 95591d991a7db897328b7ac8a8bb24b4
    [+] forged tag        = 2d569092e04a258dca912d586c7c4f32
"""
import os, sys
import gf128 as gf

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = b"print_the_flag!!"


def load_seals():
    triples = []
    with open(os.path.join(HERE, "artifacts", "seals.txt")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pt, ct, tag = line.split()
            triples.append((gf.b2i(pt), gf.b2i(ct), gf.b2i(tag)))
    return triples


def main():
    seals = load_seals()
    (pA, CA, TA), (pB, CB, TB), (p0, C0, T0) = seals[0], seals[1], seals[2]

    # keystream: enc(0) = keystream, or generally P XOR C for any seal.
    keystream = p0 ^ C0
    assert keystream == (pA ^ CA) == (pB ^ CB), "keystream not constant"

    H2 = gf.mul(TA ^ TB, gf.inv(CA ^ CB))
    P = TA ^ gf.mul(CA, H2)
    valid = (gf.mul(C0, H2) ^ P) == T0
    print(f"[*] H2 = {gf.i2h(H2)}")
    print(f"[*] P  = {gf.i2h(P)}")
    print(f"[*] model validated on the held-out seal: {valid}")

    C_t = int.from_bytes(TARGET, "big") ^ keystream
    T_t = gf.mul(C_t, H2) ^ P
    print(f"[+] forged ciphertext = {gf.i2h(C_t)}")
    print(f"[+] forged tag        = {gf.i2h(T_t)}")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
