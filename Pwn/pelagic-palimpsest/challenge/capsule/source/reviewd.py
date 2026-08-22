#!/usr/bin/env python3
"""Clean source for Nereid-9's bathymetric sounding review service.

The release compiler silently replaces the audited backend import.  Keep the
protocol deliberately compact: reversing the service is part of the challenge.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys

import fastmemo_clean as _backend


MAGIC = b"DIVE"
SLOTS = 32
POSSESSION_PAGES = 6
PAGE_SIZE = 4096


def _read_exact(size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sys.stdin.buffer.read(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _write_frame(status: int, data: bytes = b"") -> None:
    sys.stdout.buffer.write(struct.pack("<BI", status, len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _proof_gate() -> None:
    nonce = os.urandom(32)
    pages_path = os.environ.get("PALIMPSEST_PAGES", "/app/clean-stage2.pages")
    with open(pages_path, "rb") as stream:
        pages = stream.read()
    if not pages or len(pages) % PAGE_SIZE:
        raise RuntimeError("bathymetry")

    page_count = len(pages) // PAGE_SIZE
    indexes: list[int] = []
    counter = 0
    while len(indexes) < POSSESSION_PAGES:
        candidate = int.from_bytes(
            hashlib.blake2s(
                b"palimpsest-page-selection-v2\0"
                + nonce
                + struct.pack("<I", counter)
            ).digest()[:4],
            "little",
        ) % page_count
        counter += 1
        if candidate not in indexes:
            indexes.append(candidate)

    sys.stdout.buffer.write(
        MAGIC
        + nonce
        + bytes([len(indexes)])
        + b"".join(struct.pack("<H", index) for index in indexes)
    )
    sys.stdout.buffer.flush()

    proof = _read_exact(32 * (1 + len(indexes)))
    with open(os.environ.get("PALIMPSEST_ROOT", "/app/divergence.root"), "rb") as stream:
        root = bytes.fromhex(stream.read().strip().decode("ascii"))
    expected = hashlib.blake2s(b"palimpsest-dive-proof-v2\0" + nonce + root).digest()
    for index in indexes:
        page = pages[index * PAGE_SIZE : (index + 1) * PAGE_SIZE]
        expected += hashlib.blake2s(
            b"palimpsest-page-possession-v2\0"
            + nonce
            + struct.pack("<H", index)
            + page
        ).digest()
    if not hmac.compare_digest(proof, expected):
        _write_frame(0xFF, b"pressure seal rejected")
        raise SystemExit(1)
    _write_frame(0, b"dive clearance granted")


def main() -> None:
    _proof_gate()
    slots: list[object | None] = [None] * SLOTS

    while True:
        header = _read_exact(2)
        opcode, slot = header
        if slot >= SLOTS:
            _write_frame(1, b"slot")
            continue

        try:
            if opcode == 1:  # NEW
                logical_len = struct.unpack("<I", _read_exact(4))[0]
                slots[slot] = _backend.new(logical_len)
                _write_frame(0)
            elif opcode == 2:  # WRITE
                offset, size = struct.unpack("<II", _read_exact(8))
                data = _read_exact(size)
                if slots[slot] is None:
                    raise ValueError("empty")
                _backend.write(slots[slot], offset, data)
                _write_frame(0)
            elif opcode == 3:  # SHOW
                if slots[slot] is None:
                    raise ValueError("empty")
                _write_frame(0, _backend.show(slots[slot]))
            elif opcode == 4:  # DROP
                slots[slot] = None
                _write_frame(0)
            elif opcode == 5:  # APPLY
                size = struct.unpack("<I", _read_exact(4))[0]
                argument = _read_exact(size)
                if slots[slot] is None:
                    raise ValueError("empty")
                _backend.lockdown()
                result = _backend.apply(slots[slot], argument)
                _write_frame(0, result if isinstance(result, bytes) else b"")
            else:
                _write_frame(1, b"opcode")
        except (ValueError, OverflowError) as error:
            _write_frame(1, str(error).encode())


if __name__ == "__main__":
    try:
        main()
    except EOFError:
        pass
