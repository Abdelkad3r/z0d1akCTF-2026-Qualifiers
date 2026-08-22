#!/usr/bin/env python3
"""
Offline reproduction for Rewind - no network required.

Reproduces the flag from the two hex strings captured during the live session
(artifacts/secret_ct.hex and artifacts/keystream.hex), proving the keystream
reuse: flag = secret_ct XOR enc(0x00...).

    $ python3 verify_offline.py
    [+] zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, "artifacts", name)) as f:
        return bytes.fromhex(f.read().strip())


def main():
    secret_ct = load("secret_ct.hex")   # flag encrypted under the keystream
    keystream = load("keystream.hex")    # = enc(0x00 * len(secret_ct))
    assert len(secret_ct) == len(keystream), "length mismatch"

    flag = bytes(a ^ b for a, b in zip(secret_ct, keystream))
    text = flag.decode(errors="replace")

    ok = text.startswith("zdk{") and text.endswith("}")
    print(f"[+] {text}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
