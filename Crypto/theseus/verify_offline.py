#!/usr/bin/env python3
"""Verify the captured THESEUS derivation without a live instance.

Foundry's `cast` is used only for Ethereum Keccak-256. Python's hashlib.sha3_256
implements the standardized SHA-3 variant and is not byte-compatible with EVM
KECCAK256.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


BASE = Path(__file__).resolve().parent


def keccak(data: bytes) -> str:
    return subprocess.check_output(
        ["cast", "keccak", "0x" + data.hex()], text=True
    ).strip().lower()


def raw(word: str) -> bytes:
    return bytes.fromhex(word.removeprefix("0x"))


def main() -> None:
    if shutil.which("cast") is None:
        raise SystemExit("[-] Foundry `cast` is required")

    solution = json.loads((BASE / "artifacts/accepted-solution.json").read_text())
    records = json.loads((BASE / "artifacts/ledger-records.json").read_text())

    leaves = [keccak(raw(record["canonicalRecord"])) for record in records]
    level = leaves
    while len(level) > 1:
        level = [
            keccak(raw(level[index]) + raw(level[index + 1]))
            for index in range(0, len(level), 2)
        ]
    assert level[0] == solution["harbourRoot"]

    selected_index = solution["selectedIndex"]
    assert leaves[selected_index] == solution["selectedLeaf"]
    node = solution["selectedLeaf"]
    index = selected_index
    for sibling in solution["siblings"]:
        material = raw(sibling) + raw(node) if index & 1 else raw(node) + raw(sibling)
        node = keccak(material)
        index >>= 1
    assert node == solution["harbourRoot"]

    state_material = b"".join(
        raw(solution[name])
        for name in ("firstMark", "secondMark", "harbourRoot", "proofSalt")
    )
    assert keccak(state_material) == solution["stateProofMark"]

    flag_blob = bytes.fromhex(
        (BASE / "artifacts/setup-deployment-flag-fragment.hex").read_text().strip()
    )
    flag = re.search(rb"zdk\{[\x20-\x7e]*?\}", flag_blob).group().decode()
    assert flag == solution["flag"]

    print(f"[+] 8 ledger leaves -> {solution['harbourRoot']}")
    print(f"[+] Merkle path for leaf {selected_index} verified")
    print(f"[+] state proof mark -> {solution['stateProofMark']}")
    print(f"[+] flag -> {flag}")


if __name__ == "__main__":
    main()
