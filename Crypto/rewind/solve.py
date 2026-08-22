#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - Rewind (Cryptography, 120 pts)

The service is a stream cipher whose keystream is reused for every encryption in
a session ("the counter keeps rewinding"). It prints `secret_ct` (the flag
encrypted under that keystream) and offers an oracle that encrypts
attacker-controlled bytes under the *same* keystream.

Attack (keystream reuse / two-time pad):
    ct = pt XOR keystream
Encrypt an all-zero plaintext:
    enc(0x00...) = 0x00... XOR keystream = keystream        <- keystream recovered
Recover the flag:
    flag = secret_ct XOR keystream

Usage:
    python3 solve.py [host] [port]
    python3 solve.py rewind-<id>.chals.z0d1ak.org 1337
"""
import socket, ssl, re, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "rewind-011fb3f6de4d.chals.z0d1ak.org"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337


def connect():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=20)
    return ctx.wrap_socket(raw, server_hostname=HOST)


def recv_until(s, marker=b"> ", timeout=15):
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


def grab_hex(text, label):
    m = re.search(label + r"\s*=\s*([0-9a-fA-F]+)", text)
    return bytes.fromhex(m.group(1)) if m else None


def main():
    # A couple of retries: the challenge is an instancer and can be briefly flaky.
    last_err = None
    for attempt in range(4):
        try:
            s = connect()
            banner = recv_until(s).decode(errors="replace")
            if "secret_ct" not in banner:
                raise RuntimeError("no secret_ct in banner")
            break
        except Exception as e:
            last_err = e
            time.sleep(2)
    else:
        print(f"[-] could not reach service: {last_err!r}")
        return 1

    sys.stdout.write(banner)
    secret_ct = grab_hex(banner, "secret_ct")
    n = len(secret_ct)
    print(f"\n[*] secret_ct is {n} bytes")

    # Menu option [2]: encrypt attacker-controlled bytes. Feed n zero bytes so the
    # returned ciphertext IS the keystream.
    s.sendall(b"2\n")
    recv_until(s, b">", timeout=10)          # "hex plaintext >"
    s.sendall(("00" * n).encode() + b"\n")
    resp = recv_until(s).decode(errors="replace")
    keystream = grab_hex(resp, "ct")
    print(f"[*] recovered keystream: {keystream.hex()}")

    flag = bytes(a ^ b for a, b in zip(secret_ct, keystream))
    print(f"[+] FLAG: {flag.decode(errors='replace')}")

    try:
        s.sendall(b"3\n")
        s.close()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
