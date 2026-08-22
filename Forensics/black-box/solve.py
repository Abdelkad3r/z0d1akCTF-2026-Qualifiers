#!/usr/bin/env python3
"""z0d1akCTF 2026 Qualifiers - Forensics - "Black Box"

Recovers the flag from the recovered flight-recorder image `blackbox.bin`.

Container format (reverse engineered, see README.md):

    offset  size  field
    0       2     magic  b"BX"
    2       1     record type   (1 = GPS, 2 = telemetry, 3 = flag fragment)
    3       1     flags         (always 0)
    4       2     sequence number, BIG endian
    6       8     payload
    14      2     trailer, BIG endian

Every multi-byte field is big-endian - that is the "unclassified
architecture" the brief refers to, and why little-endian-assuming tools
show nothing useful.

The trailer doubles as a per-type key/checksum:

    type 1  ->  (seq * 0x1337) & 0xFFFF
    type 2  ->  (seq * 0x4242) & 0xFFFF
    type 3  ->  0xDEAD  (constant - it is the XOR key for the payload)

The five type-3 records are physically out of order in the image (the
"impact damage"). Sorting them by sequence number, concatenating the
payloads and XOR-ing with the repeating key DE AD yields the flag; the
three trailing pad bytes decode to 0x00, which confirms the key.

Usage:  python3 solve.py [blackbox.bin]
"""
from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path

MAGIC = b"BX"
RECORD_SIZE = 16
XOR_KEY = b"\xde\xad"

TYPE_GPS, TYPE_TELEMETRY, TYPE_FRAGMENT = 1, 2, 3
TRAILER_MULTIPLIER = {TYPE_GPS: 0x1337, TYPE_TELEMETRY: 0x4242}


class Record:
    __slots__ = ("offset", "type", "flags", "seq", "payload", "trailer")

    def __init__(self, offset: int, raw: bytes) -> None:
        if raw[:2] != MAGIC:
            raise ValueError(f"bad magic at offset {offset:#x}: {raw[:2]!r}")
        self.offset = offset
        self.type = raw[2]
        self.flags = raw[3]
        self.seq = struct.unpack(">H", raw[4:6])[0]
        self.payload = raw[6:14]
        self.trailer = struct.unpack(">H", raw[14:16])[0]

    @property
    def trailer_ok(self) -> bool:
        """Type 1/2 trailers are seq-derived checksums; type 3 is a constant."""
        if self.type in TRAILER_MULTIPLIER:
            return self.trailer == (self.seq * TRAILER_MULTIPLIER[self.type]) & 0xFFFF
        return self.trailer == 0xDEAD


def parse(image: bytes) -> list[Record]:
    if len(image) % RECORD_SIZE:
        raise ValueError(f"image is not a whole number of {RECORD_SIZE}-byte records")
    return [Record(o, image[o:o + RECORD_SIZE]) for o in range(0, len(image), RECORD_SIZE)]


def recover_flag(records: list[Record]) -> str:
    fragments = sorted((r for r in records if r.type == TYPE_FRAGMENT), key=lambda r: r.seq)
    if [r.seq for r in fragments] != list(range(len(fragments))):
        raise ValueError("flag fragment sequence numbers are not contiguous")
    blob = b"".join(r.payload for r in fragments)
    plain = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(blob))
    body, _, pad = plain.partition(b"\x00")
    if pad.strip(b"\x00"):
        raise ValueError("trailing bytes are not clean padding - wrong key?")
    return body.decode("ascii")


def write_csv(records: list[Record], path: Path) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["offset", "type", "seq", "trailer", "trailer_ok", "decoded"])
        for r in records:
            if r.type == TYPE_GPS:
                lat, lon = struct.unpack(">ff", r.payload)
                decoded = f"lat={lat:.5f} lon={lon:.5f}"
            elif r.type == TYPE_TELEMETRY:
                alt, batt, baro, tick = struct.unpack(">HHHH", r.payload)
                decoded = f"alt={alt} batt={batt} baro={baro} tick={tick}"
            else:
                decoded = r.payload.hex(" ")
            w.writerow([f"{r.offset:#06x}", r.type, r.seq, f"{r.trailer:#06x}",
                        r.trailer_ok, decoded])


def main(argv: list[str]) -> int:
    image_path = Path(argv[1]) if len(argv) > 1 else Path(__file__).parent / "challenge" / "blackbox.bin"
    records = parse(image_path.read_bytes())

    by_type: dict[int, list[Record]] = {}
    for r in records:
        by_type.setdefault(r.type, []).append(r)

    print(f"{image_path.name}: {len(records)} records")
    for t in sorted(by_type):
        group = by_type[t]
        bad = [r for r in group if not r.trailer_ok]
        print(f"  type {t}: {len(group):3d} records, "
              f"seq {min(r.seq for r in group)}..{max(r.seq for r in group)}, "
              f"{len(bad)} bad trailers")

    frags = sorted(by_type[TYPE_FRAGMENT], key=lambda r: r.seq)
    print("\n  flag fragments (physical order -> logical order):")
    for r in sorted(frags, key=lambda r: r.offset):
        print(f"    {r.offset:#06x}  seq {r.seq}  {r.payload.hex(' ')}")

    flag = recover_flag(records)
    print(f"\nFlag: {flag}")

    out = Path(__file__).parent / "artifacts"
    if out.is_dir():
        write_csv(records, out / "records.csv")
        print(f"Wrote {out / 'records.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
