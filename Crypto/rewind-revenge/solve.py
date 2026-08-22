#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - Rewind Revenge (Cryptography, 123 pts)

AES-GCM nonce reuse ("the forbidden attack"). The service seals 16-byte commands
under a FIXED nonce and refuses to seal privileged commands. For a single-block
message the GCM tag is linear in GF(2^128):

    T = C . H^2  XOR  P          (H = GHASH key, P constant for a fixed nonce)

Two seals eliminate P and yield H^2; a third validates the model. We then forge
a tag for the privileged plaintext `print_the_flag!!` and submit it.

    python3 solve.py [host] [port]
"""
import socket, ssl, re, sys, time
import gf128 as gf

HOST = sys.argv[1] if len(sys.argv) > 1 else "rewind-revenge-5fddcbd9c91d.chals.z0d1ak.org"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TARGET = b"print_the_flag!!"


def connect():
    last = None
    for _ in range(8):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((HOST, PORT), timeout=20)
            return ctx.wrap_socket(raw, server_hostname=HOST)
        except Exception as e:      # instancer can be briefly flaky / rate-limited
            last = e
            time.sleep(3)
    raise last


def recv_until(s, marker=b">", timeout=15):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def seal(s, hexpt):
    s.sendall(b"1\n")
    recv_until(s, b">", 8)                   # "hex plaintext ... >"
    s.sendall(hexpt.encode() + b"\n")
    r = recv_until(s).decode(errors="replace")
    C = re.search(r"ciphertext\s*=\s*([0-9a-f]+)", r).group(1)
    T = re.search(r"tag\s*=\s*([0-9a-f]+)", r).group(1)
    return gf.b2i(C), gf.b2i(T)


def main():
    s = connect()
    recv_until(s)                            # banner

    # 1) Query the sealing oracle.
    CA, TA = seal(s, "41" * 16)
    CB, TB = seal(s, "42" * 16)
    C0, T0 = seal(s, "00" * 16)              # enc(0) reveals the keystream directly
    keystream = C0

    # 2) Recover H^2 and P from the linear model, validate on the third seal.
    H2 = gf.mul(TA ^ TB, gf.inv(CA ^ CB))
    P = TA ^ gf.mul(CA, H2)
    assert gf.mul(C0, H2) ^ P == T0, "model validation failed"
    print(f"[*] H2        = {gf.i2h(H2)}")
    print(f"[*] P         = {gf.i2h(P)}")
    print(f"[*] keystream = {gf.i2h(keystream)}")
    print("[*] model validated against an independent third seal")

    # 3) Forge (ciphertext, tag) for the privileged command.
    C_t = int.from_bytes(TARGET, "big") ^ keystream
    T_t = gf.mul(C_t, H2) ^ P
    print(f"[*] forged ciphertext = {gf.i2h(C_t)}")
    print(f"[*] forged tag        = {gf.i2h(T_t)}")

    # 4) Submit it.
    s.sendall(b"2\n")
    recv_until(s, b">", 8)                    # ciphertext prompt
    s.sendall(gf.i2h(C_t).encode() + b"\n")
    recv_until(s, b">", 8)                    # tag prompt
    s.sendall(gf.i2h(T_t).encode() + b"\n")

    resp = recv_until(s, b"__never__", timeout=8).decode(errors="replace")
    m = re.search(r"(zdk\{[^}]*\})", resp)
    if m:
        print(f"[+] FLAG: {m.group(1)}")
        return 0
    print("[-] no flag in response:\n" + resp)
    return 1


if __name__ == "__main__":
    sys.exit(main())
