#!/usr/bin/env python3
"""Solve z0d1akCTF 2026's You Have Not Seen My Colors challenge."""

from __future__ import annotations

import argparse
import binascii
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ANSWER = "master_of_ctf"
TRANSCRIPTION = ("ZEK", "MASTER", "OF", "CTF")
FLAG_RE = re.compile(r"zdk\{[^}\r\n]+\}")


def paeth(a: int, b: int, c: int) -> int:
    prediction = a + b - c
    distances = (abs(prediction - a), abs(prediction - b), abs(prediction - c))
    return (a, b, c)[distances.index(min(distances))]


def read_rgb_png(path: Path) -> tuple[int, int, bytes]:
    """Decode a non-interlaced, 8-bit RGB PNG using only the standard library."""
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("input is not a PNG")

    offset = len(PNG_SIGNATURE)
    header: tuple[int, int, int, int, int, int, int] | None = None
    compressed = bytearray()

    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack_from(">I", data, offset)[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_data = data[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        actual_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            raise ValueError(f"bad CRC in {chunk_type.decode(errors='replace')} chunk")

        if chunk_type == b"IHDR":
            header = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            break
        offset += 12 + length

    if header is None:
        raise ValueError("PNG has no IHDR chunk")

    width, height, depth, color_type, compression, filtering, interlace = header
    if (depth, color_type, compression, filtering, interlace) != (8, 2, 0, 0, 0):
        raise ValueError("expected a non-interlaced, 8-bit RGB PNG")

    bytes_per_pixel = 3
    stride = width * bytes_per_pixel
    filtered = zlib.decompress(compressed)
    if len(filtered) != height * (stride + 1):
        raise ValueError("unexpected decompressed PNG size")

    pixels = bytearray()
    previous = bytearray(stride)
    cursor = 0
    for _ in range(height):
        filter_type = filtered[cursor]
        source = filtered[cursor + 1 : cursor + 1 + stride]
        cursor += stride + 1
        row = bytearray(stride)

        for x, value in enumerate(source):
            left = row[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
            above = previous[x]
            upper_left = previous[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = paeth(left, above, upper_left)
            else:
                raise ValueError(f"unsupported PNG filter {filter_type}")
            row[x] = (value + predictor) & 0xFF

        pixels.extend(row)
        previous = row

    return width, height, bytes(pixels)


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def write_mask_png(
    path: Path,
    mask: list[bool],
    width: int,
    bbox: tuple[int, int, int, int],
    scale: int = 10,
    margin: int = 2,
) -> None:
    left, top, right, bottom = bbox
    left = max(0, left - margin)
    top = max(0, top - margin)
    right = min(width, right + margin)
    source_height = len(mask) // width
    bottom = min(source_height, bottom + margin)
    output_width = (right - left) * scale
    output_height = (bottom - top) * scale

    scanlines = bytearray()
    for y in range(top, bottom):
        row = b"".join((b"\xff" if mask[y * width + x] else b"\x00") * scale for x in range(left, right))
        for _ in range(scale):
            scanlines.append(0)
            scanlines.extend(row)

    ihdr = struct.pack(">IIBBBBB", output_width, output_height, 8, 0, 0, 0, 0)
    encoded = PNG_SIGNATURE
    encoded += png_chunk(b"IHDR", ihdr)
    encoded += png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9))
    encoded += png_chunk(b"IEND", b"")
    path.write_bytes(encoded)


def extract_carrier(path: Path, output: Path) -> tuple[int, tuple[int, int, int, int]]:
    width, height, pixels = read_rgb_png(path)
    mask = [pixels[offset + 2] == 0 for offset in range(0, len(pixels), 3)]
    marked = [(index % width, index // width) for index, value in enumerate(mask) if value]
    if not marked:
        raise ValueError("no zero-valued blue pixels found")

    xs, ys = zip(*marked)
    bbox = (min(xs), min(ys), max(xs) + 1, max(ys) + 1)
    write_mask_png(output, mask, width, bbox)
    return len(marked), bbox


def submit(endpoint: str) -> str:
    url = endpoint.rstrip("/") + "/solve"
    body = urllib.parse.urlencode({"answer": ANSWER}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        response = exc.read().decode(errors="replace")
        raise RuntimeError(f"submission returned HTTP {exc.code}: {response.strip()}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", nargs="?", type=Path, default=Path("challenge/image.png"))
    parser.add_argument("--mask", type=Path, default=Path("artifacts/decoded-mask.png"))
    parser.add_argument("--endpoint", help="live private instance base URL")
    args = parser.parse_args()

    marked, bbox = extract_carrier(args.image, args.mask)
    print(f"[+] zero-valued blue pixels: {marked}")
    print(f"[+] carrier bounding box: {bbox}")
    print(f"[+] wrote carrier image: {args.mask}")
    print("[+] Elian transcription:")
    for line in TRANSCRIPTION:
        print(f"    {line}")
    print("[+] ZEK is the signature; decoded answer: " + ANSWER)

    if not args.endpoint:
        return 0

    try:
        response = submit(args.endpoint)
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"[+] endpoint response: {response.strip()}")
    match = FLAG_RE.search(response)
    if match is None:
        print("[-] response did not contain a zdk{...} flag", file=sys.stderr)
        return 1
    print(f"[+] flag: {match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
