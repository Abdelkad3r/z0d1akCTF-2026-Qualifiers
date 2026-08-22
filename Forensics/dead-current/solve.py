#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - Dead Current (Forensics, 148 pts)

Recovers the sealed incident record from a CRIU checkpoint of a Go relay.

Chain:
  1. Carve the deleted ghost file -> the IRF1 sealed incident record.
  2. Parse IRF1: streamID(16), nonce(12), ciphertext(len).
  3. Recover the RelayState master secret from process memory: it is the 32-byte
     field right after the empty {type=4,len=0} incident-record marker.
  4. Reproduce the relay's crypto (recovered from the stripped binary via gdb):
        incidentKey  = SHA256(state32 || streamID || nonce[0:8])
        keystream[i] = SHA256(incidentKey || uint32le(i))     # main.xorStream
        plaintext    = ciphertext XOR keystream

Usage:
    python3 solve.py                # extracts challenge/forensics_dead-current.zip
    python3 solve.py /path/to/images   # use an already-unpacked images/ dir
"""
import hashlib, re, struct, os, sys, zipfile, tarfile, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def get_images_dir():
    if len(sys.argv) > 1:
        return sys.argv[1]
    tmp = tempfile.mkdtemp()
    z = os.path.join(HERE, "challenge", "forensics_dead-current.zip")
    with zipfile.ZipFile(z) as zf:
        zf.extractall(tmp)                        # -> dead-current-player.zip
    inner = os.path.join(tmp, "dead-current-player.zip")
    with zipfile.ZipFile(inner) as zf:
        zf.extractall(tmp)                        # -> dead-current/{checkpoint.tar,...}
    images = os.path.join(tmp, "images")
    os.makedirs(images, exist_ok=True)
    with tarfile.open(os.path.join(tmp, "dead-current", "checkpoint.tar")) as t:
        t.extractall(images)
    return images


def main():
    IMG = get_images_dir()
    load = lambda n: open(os.path.join(IMG, n), "rb").read()

    # 1. deleted ghost file -> IRF1 record
    ghost = load("ghost-file-1.img")
    size = struct.unpack("<I", ghost[8:12])[0]      # CRIU: magic(8) + u32 size + GhostFileEntry
    irf = ghost[12 + size:]
    assert irf[:4] == b"IRF1", "ghost content is not an IRF1 record"

    # 2. parse IRF1: magic(4) hdr(4) streamID(16) nonce(12) len(u32) ciphertext
    streamID = irf[8:24]
    nonce = irf[24:36]
    clen = struct.unpack("<I", irf[36:40])[0]
    ct = irf[40:40 + clen]
    print(f"[*] streamID = {streamID.hex()}")
    print(f"[*] nonce    = {nonce.hex()}   (ctx8 = first 8 bytes)")
    print(f"[*] ciphertext = {clen} bytes")

    # 3+4. recover master secret from memory and decrypt
    pages = load("pages-2.img")

    def derive(state32):
        return hashlib.sha256(state32 + streamID + nonce[:8]).digest()

    def xor_stream(key, data):                      # main.xorStream
        out = bytearray()
        i = 0
        while len(out) < len(data):
            out += hashlib.sha256(key + i.to_bytes(4, "little")).digest()
            i += 1
        return bytes(a ^ b for a, b in zip(data, out))

    for m in re.finditer(b"\x04\x00\x00\x00\x00\x00\x00\x00", pages):  # {type=4,len=0}
        state32 = pages[m.end():m.end() + 32]
        pt = xor_stream(derive(state32), ct)
        fm = re.search(rb"zdk\{[ -~]*\}", pt)
        if fm:
            print(f"[*] master secret @ pages-2 0x{m.end():x}: {state32.hex()}")
            print(f"[*] incident record: {pt[:pt.index(b'}')+1]!r}")
            print(f"\n[+] FLAG: {fm.group().decode()}")
            return 0
    print("[-] flag not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
