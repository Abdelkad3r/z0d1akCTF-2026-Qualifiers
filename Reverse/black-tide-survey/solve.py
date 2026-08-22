#!/usr/bin/env python3
"""Recover the Black Tide Survey images and decode the marked vessel."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import math
import shutil
import struct
import tempfile
import zlib
from array import array
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

ARCHIVE_SHA256 = "a1179be94dd993bb996ed217cb5a7735e1dbf75daf3725932f1bfbb36a8c16c8"
HEADER = struct.Struct("<4sHHIHHIIII")
RECORD_HEADER = struct.Struct("<4sII")
PING_HEADER = struct.Struct("<IIiihHI")
EXPECTED_BODY = "S4Ble_54_T3L0"
VESSEL_ID = "SABLE-7319"


@dataclass(frozen=True)
class Ping:
    sequence: int
    timestamp_ms: int
    x_mm: int
    y_mm: int
    heading_raw: int
    altitude_mm: int
    flags: int
    port: tuple[int, ...]
    starboard: tuple[int, ...]


@dataclass(frozen=True)
class Recording:
    recording_id: int
    bins: int
    near_mm: int
    sample_rate_hz: int
    flags: int
    metadata: str
    gains: tuple[int, ...]
    pings: tuple[Ping, ...]


GLYPHS = {
    (".####", "#....", "#....", ".###.", "....#", "....#", "####."): "S",
    ("...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."): "4",
    ("####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."): "B",
    (".##..", "..#..", "..#..", "..#..", "..#..", "..#..", ".###."): "l",
    (".....", ".....", ".###.", "#...#", "#####", "#....", ".###."): "e",
    (".....", ".....", ".....", ".....", ".....", ".....", "#####"): "_",
    ("#####", "#....", "####.", "....#", "....#", "#...#", ".###."): "5",
    ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."): "T",
    ("####.", "....#", "....#", ".###.", "....#", "....#", "####."): "3",
    ("#....", "#....", "#....", "#....", "#....", "#....", "#####"): "L",
    (".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."): "0",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_bank(packed: bytes, bins: int) -> tuple[int, ...]:
    """Unpack two 12-bit words per triple and reverse ZigZag deltas."""
    if len(packed) * 2 != bins * 3:
        raise ValueError("invalid packed bank length")

    words: list[int] = []
    for offset in range(0, len(packed), 3):
        b0, b1, b2 = packed[offset : offset + 3]
        words.append(b0 | ((b1 & 0x0F) << 8))
        words.append((b1 >> 4) | (b2 << 4))

    samples = [words[0]]
    for word in words[1:]:
        delta = (word >> 1) ^ -(word & 1)
        samples.append((samples[-1] + delta) & 0xFFF)
    return tuple(samples)


def load_bts(path: Path) -> Recording:
    blob = path.read_bytes()
    if len(blob) < HEADER.size:
        raise ValueError(f"{path}: truncated header")

    (
        magic,
        version,
        header_size,
        recording_id,
        bins,
        expected_pings,
        near_mm,
        sample_rate_hz,
        flags,
        stored_crc,
    ) = HEADER.unpack_from(blob)
    if magic != b"BTS2" or version != 2 or header_size != HEADER.size:
        raise ValueError(f"{path}: unsupported BTS2 header")
    if binascii.crc32(blob[:28]) & 0xFFFFFFFF != stored_crc:
        raise ValueError(f"{path}: header CRC mismatch")

    metadata = ""
    gains = (256,) * 32
    pings: list[Ping] = []
    offset = header_size
    while offset + RECORD_HEADER.size <= len(blob):
        tag, size, record_crc = RECORD_HEADER.unpack_from(blob, offset)
        offset += RECORD_HEADER.size
        payload = blob[offset : offset + size]
        offset += size
        if len(payload) != size:
            raise ValueError(f"{path}: truncated {tag!r} record")
        if binascii.crc32(payload) & 0xFFFFFFFF != record_crc:
            raise ValueError(f"{path}: {tag!r} record CRC mismatch")

        if tag == b"META":
            metadata = payload.decode("ascii").rstrip()
        elif tag == b"CALB":
            if len(payload) != 64:
                raise ValueError(f"{path}: unexpected CALB size")
            gains = struct.unpack("<32H", payload)
        elif tag == b"PING":
            expected_size = PING_HEADER.size + bins * 3
            if len(payload) != expected_size:
                raise ValueError(f"{path}: unexpected PING size")
            fields = PING_HEADER.unpack_from(payload)
            bank_size = bins * 3 // 2
            port = decode_bank(
                payload[PING_HEADER.size : PING_HEADER.size + bank_size], bins
            )
            starboard = decode_bank(payload[PING_HEADER.size + bank_size :], bins)
            pings.append(Ping(*fields, port, starboard))
        elif tag == b"DONE":
            break

    if len(pings) != expected_pings:
        raise ValueError(f"{path}: expected {expected_pings} pings, got {len(pings)}")
    return Recording(
        recording_id,
        bins,
        near_mm,
        sample_rate_hz,
        flags,
        metadata,
        gains,
        tuple(pings),
    )


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def write_gray_png(path: Path, width: int, height: int, pixels: bytes) -> None:
    if len(pixels) != width * height:
        raise ValueError("pixel buffer has the wrong size")
    scanlines = bytearray()
    for row in range(height):
        scanlines.append(0)
        start = row * width
        scanlines.extend(pixels[start : start + width])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += png_chunk(b"IHDR", ihdr)
    png += png_chunk(b"IDAT", zlib.compress(bytes(scanlines), 9))
    png += png_chunk(b"IEND", b"")
    path.write_bytes(png)


def nearest_crop(
    pixels: bytes,
    width: int,
    box: tuple[int, int, int, int],
    scale: int,
) -> tuple[int, int, bytes]:
    left, top, right, bottom = box
    output = bytearray()
    for y in range(top, bottom):
        row = pixels[y * width + left : y * width + right]
        enlarged = b"".join(bytes((value,)) * scale for value in row)
        for _ in range(scale):
            output.extend(enlarged)
    return (right - left) * scale, (bottom - top) * scale, bytes(output)


def diagnostic_image(recording: Recording) -> bytes:
    """Reproduce sonar_diag: reverse port, append starboard, and truncate to 8-bit."""
    output = bytearray()
    for ping in recording.pings:
        output.extend(value >> 4 for value in reversed(ping.port))
        output.extend(value >> 4 for value in ping.starboard)
    return bytes(output)


def decode_marker(pixels: bytes, width: int) -> str:
    """Read the 13 fixed-pitch 5x7 glyphs visible in the diagnostic frame."""
    chars: list[str] = []
    for index in range(13):
        x = 480 + index * 18
        rows = tuple(
            "".join(
                "#"
                if pixels[(340 + gy * 3 + 1) * width + x + gx * 3 + 1] > 128
                else "."
                for gx in range(5)
            )
            for gy in range(7)
        )
        if rows not in GLYPHS:
            raise ValueError(f"unknown marker glyph {index}: {rows}")
        chars.append(GLYPHS[rows])
    return "".join(chars)


def splat(
    accumulator: array,
    weights: array,
    width: int,
    height: int,
    column: float,
    row: float,
    intensity: float,
) -> None:
    if column < 0 or row < 0 or column > width - 1 or row > height - 1:
        return
    c0 = math.floor(column)
    r0 = math.floor(row)
    dc = column - c0
    dr = row - r0
    for rr, cc, weight in (
        (r0, c0, (1.0 - dr) * (1.0 - dc)),
        (r0, c0 + 1, (1.0 - dr) * dc),
        (r0 + 1, c0, dr * (1.0 - dc)),
        (r0 + 1, c0 + 1, dr * dc),
    ):
        if rr < height and cc < width:
            position = rr * width + cc
            accumulator[position] += intensity * weight
            weights[position] += weight


def reconstruct(
    recording: Recording,
    *,
    width: int,
    height: int,
    x_extent_mm: float,
    y_extent_mm: float,
) -> bytes:
    """Ground-correct and georeference both sonar banks with bilinear splatting."""
    accumulator = array("d", [0.0]) * (width * height)
    weights = array("d", [0.0]) * (width * height)
    bin_spacing_mm = 1_000_000.0 / recording.sample_rate_hz

    for ping in sorted(recording.pings, key=lambda item: item.sequence):
        heading = math.radians(ping.heading_raw * 0.001)
        sin_heading = math.sin(heading)
        cos_heading = math.cos(heading)

        for side, samples, gains in (
            (-1, ping.port, recording.gains[:16]),
            (1, ping.starboard, recording.gains[16:]),
        ):
            for index, sample in enumerate(samples):
                # The SSX-27R stores its starboard bank from far to near.
                range_index = index if side == -1 else recording.bins - 1 - index
                slant = recording.near_mm + range_index * bin_spacing_mm
                if slant < ping.altitude_mm:
                    continue
                ground = math.sqrt(slant * slant - ping.altitude_mm * ping.altitude_mm)
                world_x = ping.x_mm + side * ground * sin_heading
                world_y = ping.y_mm - side * ground * cos_heading
                column = (world_x + x_extent_mm) * (width - 1) / (2.0 * x_extent_mm)
                row = (y_extent_mm - world_y) * (height - 1) / (2.0 * y_extent_mm)
                gain = gains[index // 24]
                intensity = min(255.0, (sample / 16.0) * gain / 256.0)
                splat(accumulator, weights, width, height, column, row, intensity)

    output = bytearray(width * height)
    for index, total in enumerate(accumulator):
        if weights[index]:
            output[index] = min(255, int(total / weights[index]))
    return bytes(output)


def solve(archive: Path, output_dir: Path, skip_maps: bool) -> str:
    if sha256(archive) != ARCHIVE_SHA256:
        raise ValueError(
            "handout SHA-256 does not match the expected challenge archive"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="black-tide-") as temporary:
        extracted = Path(temporary)
        with ZipFile(archive) as handout:
            handout.extractall(extracted)

        dock = load_bts(extracted / "dock_calibration.bts")
        final = load_bts(extracted / "final_transect.bts")
        shutil.copyfile(
            extracted / "dock_reference.png", output_dir / "dock-reference.png"
        )

        raw = diagnostic_image(final)
        raw_width = final.bins * 2
        write_gray_png(
            output_dir / "raw-diagnostic.png", raw_width, len(final.pings), raw
        )
        crop_width, crop_height, crop = nearest_crop(
            raw, raw_width, (462, 329, 768, 395), 5
        )
        write_gray_png(output_dir / "flag-marker.png", crop_width, crop_height, crop)
        body = decode_marker(raw, raw_width)
        if body != EXPECTED_BODY:
            raise ValueError(f"unexpected marker body: {body}")

        if not skip_maps:
            dock_map = reconstruct(
                dock,
                width=640,
                height=640,
                x_extent_mm=8666.667,
                y_extent_mm=8666.667,
            )
            write_gray_png(output_dir / "dock-reconstructed.png", 640, 640, dock_map)

            final_map = reconstruct(
                final,
                width=1024,
                height=640,
                x_extent_mm=13866.667,
                y_extent_mm=8666.667,
            )
            write_gray_png(output_dir / "final-survey.png", 1024, 640, final_map)
            crop_width, crop_height, crop = nearest_crop(
                final_map, 1024, (100, 410, 860, 600), 3
            )
            write_gray_png(output_dir / "vessel-id.png", crop_width, crop_height, crop)

    print(f"archive    = {sha256(archive)}")
    print(f"dock meta  = {dock.metadata.replace(chr(10), ', ')}")
    print(f"final meta = {final.metadata.replace(chr(10), ', ')}")
    print(
        f"ping order = evens first, then odds; sorted {len(final.pings)} pings by sequence"
    )
    print(f"vessel     = {VESSEL_ID}")
    print(f"marker     = {body}")
    print(f"flag       = zdk{{{body}}}")
    return body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "archive",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("challenge") / "rev_black-tide-survey.zip",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).with_name("generated"),
        help="directory for recovered PNG files (default: ./generated)",
    )
    parser.add_argument(
        "--skip-maps",
        action="store_true",
        help="decode the flag without performing the slower georeferencing step",
    )
    arguments = parser.parse_args()
    solve(arguments.archive, arguments.output_dir, arguments.skip_maps)


if __name__ == "__main__":
    main()
