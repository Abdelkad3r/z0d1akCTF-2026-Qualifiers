#!/usr/bin/env python3
"""Forge a cyclotomic-echo signature from the recovered NTRU basis."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
from pathlib import Path


N = 128
DOMAIN = b"cyclotomic-echo/sign/v2"
FLAG_RE = re.compile(r"zdk\{[^}\r\n]+\}")


def add(a: list[int], b: list[int]) -> list[int]:
    return [x + y for x, y in zip(a, b)]


def sub(a: list[int], b: list[int]) -> list[int]:
    return [x - y for x, y in zip(a, b)]


def negate(a: list[int]) -> list[int]:
    return [-x for x in a]


def multiply(a: list[int], b: list[int]) -> list[int]:
    """Multiply in Z[x]/(x^N + 1)."""
    product = [0] * (2 * N - 1)
    for i, x in enumerate(a):
        if x == 0:
            continue
        for j, y in enumerate(b):
            if y:
                product[i + j] += x * y
    for degree in range(2 * N - 2, N - 1, -1):
        product[degree - N] -= product[degree]
    return product[:N]


def conjugate(a: list[int]) -> list[int]:
    return [a[0]] + [-a[N - i] for i in range(1, N)]


def gram_entries(key: dict[str, list[int]]) -> tuple[list[int], list[int]]:
    f, g, big_f, big_g = key["f"], key["g"], key["F"], key["G"]
    q00 = add(multiply(f, conjugate(f)), multiply(g, conjugate(g)))
    q10 = add(multiply(big_f, conjugate(f)), multiply(big_g, conjugate(g)))
    return q00, q10


def hash_to_point(instance: dict, salt: bytes) -> tuple[list[int], list[int]]:
    message = bytes.fromhex(instance["target_hex"])
    digest = hashlib.shake_256(
        DOMAIN
        + bytes.fromhex(instance["instance_id"])
        + len(message).to_bytes(4, "little")
        + message
        + salt
    ).digest(N // 4)
    bits = [(digest[i >> 3] >> (i & 7)) & 1 for i in range(2 * N)]
    return bits[:N], bits[N:]


def forge(instance: dict, key: dict[str, list[int]], salt: bytes) -> tuple[dict, int]:
    f, g, big_f, big_g = key["f"], key["g"], key["F"], key["G"]

    determinant = sub(multiply(f, big_g), multiply(g, big_f))
    if determinant != [1] + [0] * (N - 1):
        raise ValueError("recovery tuple is not a unimodular basis")

    q00, q10 = gram_entries(key)
    half = instance["q00_half"]
    public_q00 = half + [0] + [-half[i] for i in range(N // 2 - 1, 0, -1)]
    if q00 != public_q00 or q10 != instance["q10"]:
        raise ValueError("recovery basis does not match the live public form")

    x, y = hash_to_point(instance, salt)

    # Map the hash coset through B=[[f,g],[F,G]], choose the smallest
    # coefficient representatives modulo 2, then map back through B^-1.
    z0 = [value & 1 for value in add(multiply(x, f), multiply(y, big_f))]
    z1 = [value & 1 for value in add(multiply(x, g), multiply(y, big_g))]

    e0 = sub(multiply(z0, big_g), multiply(z1, big_f))
    e1 = add(negate(multiply(z0, g)), multiply(z1, f))

    first_nonzero = next((value for value in e1 if value), 0)
    if first_nonzero == 0:
        raise ValueError("degenerate second signature component")
    if first_nonzero < 0:
        e0, e1 = negate(e0), negate(e1)

    if any((a - b) % 2 for a, b in zip(x, e0)):
        raise ValueError("first component has the wrong parity")
    if any((a - b) % 2 for a, b in zip(y, e1)):
        raise ValueError("second component has the wrong parity")

    s1 = [(a - b) // 2 for a, b in zip(y, e1)]

    check_z0 = add(multiply(e0, f), multiply(e1, big_f))
    check_z1 = add(multiply(e0, g), multiply(e1, big_g))
    norm = sum(value * value for value in check_z0 + check_z1)
    if norm > instance["bound"]:
        raise ValueError(f"forgery norm {norm} exceeds bound {instance['bound']}")

    return {"salt_hex": salt.hex(), "s1": s1}, norm


def receive_line(stream) -> dict:
    line = stream.readline()
    if not line:
        raise ConnectionError("service closed the connection")
    return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", nargs="?", type=int, default=1337)
    parser.add_argument(
        "--recovery",
        type=Path,
        default=Path("challenge/recovery.json"),
    )
    parser.add_argument("--instance-out", type=Path)
    parser.add_argument("--forgery-out", type=Path)
    args = parser.parse_args()

    key = json.loads(args.recovery.read_text())
    context = ssl.create_default_context()
    with socket.create_connection((args.host, args.port), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=args.host) as connection:
            stream = connection.makefile("rwb", buffering=0)
            instance = receive_line(stream)
            forgery, norm = forge(instance, key, bytes(16))

            print(f"[*] instance: {instance['instance_id']}")
            print("[+] recovery basis matches the public Gram matrix")
            print(f"[+] forged norm: {norm} <= {instance['bound']}")
            print(f"[+] max |s1[i]|: {max(map(abs, forgery['s1']))}")

            if args.instance_out:
                args.instance_out.write_text(json.dumps(instance, indent=2) + "\n")
            if args.forgery_out:
                args.forgery_out.write_text(json.dumps(forgery, indent=2) + "\n")

            stream.write(json.dumps(forgery, separators=(",", ":")).encode() + b"\n")
            response = receive_line(stream)
            print("[+] response: " + json.dumps(response, separators=(",", ":")))

    match = FLAG_RE.search(json.dumps(response))
    if match is None:
        raise RuntimeError("service response did not contain a flag")
    print(f"[+] flag: {match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
