#!/usr/bin/env python3
"""
99.8% (z0d1akCTF 2026 Qualifiers) -- forensic solver.

An interrupted qBittorrent download. Every plaintext zdk{...} in the evidence is a
decoy (pH4K3_*, d3c0Y_*). The real flag is recovered with the "qbcn" scheme the
logs describe:

    key            = sha256(domain || piece_window || piece_length_word)
    keystream[n]   = sha256(key || uint32le(n))          # 32-byte blocks, n = 0,1,2,...
    keycheck       = sha256(key)[0:8]

where (recovered from the evidence):
    domain             = b"ninety-eight/qbcn/v1\x00"     # memory-dump KDF trace
    piece_window       = pieces[0:320]                   # first 16 SHA-1 piece hashes
    piece_length_word  = uint32le(131072)                # torrent 'piece length'

The file's final partial piece (index 16) inside the .!qB partfile is an "HREG"
container holding the keycheck + an XOR-encrypted "QBCN" record; decrypting it
yields the flag.

Run from the extracted `evidence/` directory (or pass its path):
    python3 solve.py [path/to/evidence]
"""

import sys
import os
import struct
import hashlib
import re

EV = sys.argv[1] if len(sys.argv) > 1 else "evidence"
TORRENT = os.path.join(EV, "session/BT_backup/"
                       "7a1465326157c2e764a7c9400ace002f51058c28.torrent")
PARTFILE = os.path.join(EV, "fragments/download.tmp.!qB")

DOMAIN = b"ninety-eight/qbcn/v1\x00"        # from memory/qbcore_2025_11_18.mem KDF trace


def torrent_field(raw, key):
    """Minimal bencode field extractor: returns the raw bytes/int after b'<len>:<key>'."""
    i = raw.find(b"%d:%s" % (len(key), key))
    if i < 0:
        raise KeyError(key)
    i += len(key) + len(str(len(key))) + 1
    if raw[i:i + 1] == b"i":                 # integer
        return int(raw[i + 1:raw.index(b"e", i)])
    j = raw.index(b":", i)                    # string
    n = int(raw[i:j])
    return raw[j + 1:j + 1 + n]


def keystream(key, n_bytes, n0=0):
    out = bytearray()
    n = n0
    while len(out) < n_bytes:
        out += hashlib.sha256(key + struct.pack("<I", n)).digest()
        n += 1
    return bytes(out[:n_bytes])


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    raw = open(TORRENT, "rb").read()
    piece_length = torrent_field(raw, b"piece length")
    pieces = torrent_field(raw, b"pieces")
    print(f"[*] piece length = {piece_length}")
    print(f"[*] {len(pieces)} bytes of piece hashes ({len(pieces)//20} full SHA-1 hashes)")

    # ---- derive the qbcn key ----
    piece_window = pieces[0:320]                       # first 16 piece hashes
    piece_length_word = struct.pack("<I", piece_length)
    key = hashlib.sha256(DOMAIN + piece_window + piece_length_word).digest()
    keycheck = hashlib.sha256(key).digest()[:8]
    print(f"[*] key      = {key.hex()}")
    print(f"[*] keycheck = {keycheck.hex()}  (sha256(key)[0:8])")

    # ---- parse the final-piece HREG container from the partfile ----
    part = open(PARTFILE, "rb").read()
    last = (len(part) - 1) // piece_length               # index of the final (partial) piece
    blob = part[last * piece_length:]
    magic, ver, clen = blob[:4], struct.unpack("<H", blob[4:6])[0], struct.unpack("<H", blob[6:8])[0]
    stored_kc = blob[8:16]
    print(f"[*] piece {last}: magic={magic!r} ver={ver} clen={clen} keycheck={stored_kc.hex()}")
    assert magic == b"HREG", "unexpected outer container magic"
    assert stored_kc == keycheck, "keycheck mismatch -> wrong key"
    print("[+] keycheck matches -> key confirmed")

    # ---- decrypt the inner QBCN record ----
    ciphertext = blob[16:16 + clen]
    inner = xor(ciphertext, keystream(key, len(ciphertext), n0=0))
    assert inner[:4] == b"QBCN", "inner magic mismatch"
    flag_len = struct.unpack("<H", inner[6:8])[0]
    flag = inner[8:8 + flag_len]
    print(f"[*] inner:  magic={inner[:4]!r} ver={struct.unpack('<H', inner[4:6])[0]} flaglen={flag_len}")
    print("\n[+] FLAG:", flag.decode())


if __name__ == "__main__":
    main()
