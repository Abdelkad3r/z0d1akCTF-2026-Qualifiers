#!/usr/bin/env python3
"""Offline self-test: simulate the exact siren signer with a random private key
and confirm the lattice attack recovers it. No network required.

  python3 test_local.py [nsigs] [trials]
"""
import os, sys, time
import ec, attack as A
N = ec.N

def make_instance():
    song_id = os.urandom(8).hex()
    D = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    Q = ec.mul(D)
    def rng_below(bound):
        nb = (bound.bit_length() + 7) // 8
        while True:
            v = int.from_bytes(os.urandom(nb), "big") % bound
            if v >= 1: return v
    def shaped_nonce(msg):
        prefix = A.public_pitch(song_id, msg) << A.SUFFIX_BITS
        while True:
            k = prefix | (rng_below(A.BND) - 1)
            if 1 <= k < N: return k
    def sign(msg):
        z = A.msg_hash(msg)
        while True:
            k = shaped_nonce(msg); r = ec.mul(k)[0] % N
            if r == 0: continue
            s = (pow(k, -1, N) * (z + r * D)) % N
            if s: return r, s
    return song_id, D, Q, sign

def main():
    nsigs = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    trials = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    ok = 0
    for t in range(trials):
        song_id, D, Q, sign = make_instance()
        sigs = [("verse-%d" % i,) + sign("verse-%d" % i) for i in range(nsigs)]
        t0 = time.time(); Dr = A.recover_D(sigs, song_id, Q); dt = time.time() - t0
        good = (Dr == D)
        ok += good
        print("trial %d: %s (%.1fs)" % (t, "RECOVERED" if good else "FAILED", dt))
    print("success %d/%d" % (ok, trials))

if __name__ == "__main__":
    main()
