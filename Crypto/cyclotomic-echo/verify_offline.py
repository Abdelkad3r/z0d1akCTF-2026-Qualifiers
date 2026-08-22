#!/usr/bin/env python3
"""Reproduce the captured cyclotomic-echo forgery without a live service."""

from __future__ import annotations

import json
from pathlib import Path

from solve import N, add, forge, gram_entries, hash_to_point, multiply, sub


ROOT = Path(__file__).resolve().parent


def main() -> int:
    key = json.loads((ROOT / "challenge/recovery.json").read_text())
    instance = json.loads((ROOT / "artifacts/instance.json").read_text())
    captured = json.loads((ROOT / "artifacts/forgery.json").read_text())
    salt = bytes.fromhex(captured["salt_hex"])

    f, g, big_f, big_g = key["f"], key["g"], key["F"], key["G"]
    determinant = sub(multiply(f, big_g), multiply(g, big_f))
    assert determinant == [1] + [0] * (N - 1)

    q00, q10 = gram_entries(key)
    half = instance["q00_half"]
    public_q00 = half + [0] + [-half[i] for i in range(N // 2 - 1, 0, -1)]
    assert q00 == public_q00
    assert q10 == instance["q10"]

    generated, norm = forge(instance, key, salt)
    assert generated == captured

    x, y = hash_to_point(instance, salt)
    z0 = [value & 1 for value in add(multiply(x, f), multiply(y, big_f))]
    z1 = [value & 1 for value in add(multiply(x, g), multiply(y, big_g))]
    e1 = [bit - 2 * coefficient for bit, coefficient in zip(y, captured["s1"])]

    print("[+] fG - gF = 1 in Z[x]/(x^128 + 1)")
    print("[+] q00: all 128 reconstructed coefficients match")
    print("[+] q10: all 128 reconstructed coefficients match")
    print(f"[+] hash weights: wt(x)={sum(x)}, wt(y)={sum(y)}")
    print(f"[+] reduced weights: wt(z0)={sum(z0)}, wt(z1)={sum(z1)}")
    print(f"[+] reduced norm: {sum(v * v for v in z0 + z1)}")
    print(f"[+] oriented e1 first nonzero: {next(v for v in e1 if v)}")
    print(f"[+] max |s1[i]|: {max(map(abs, captured['s1']))}")
    print(f"[+] captured forgery reproduced exactly: {generated == captured}")
    print(f"[+] norm check: {norm} <= {instance['bound']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
