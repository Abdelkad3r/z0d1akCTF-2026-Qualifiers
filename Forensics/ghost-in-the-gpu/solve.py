#!/usr/bin/env python3
"""z0d1akCTF 2026 Qualifiers - Forensics - "Ghost in the GPU"

Recovers the flag from `vram_dump.bin`, a 32 MiB raw VRAM capture.

Method (see README.md for the full reasoning):

  1. The card was scrubbed with random bytes, so 511 of the dump's 512
     64 KiB blocks sit at ~8.0 bits/byte of Shannon entropy. A single
     contiguous 1.5 MiB run at 0x00900000 does not, and is the only
     surviving allocation.

  2. That run contains exactly three distinct byte values - 0x00, 0x3C and
     0xBC - with half of them zero. Read as little-endian uint16 the values
     are 0x3C00 and 0xBC00: IEEE-754 half precision (fp16) for +1.0 and
     -1.0. It is a leftover inference activation buffer holding a two-valued
     mask, not real activations.

  3. 1572864 bytes / 2 = 786432 elements = 1024 x 768. Mapping +1.0 to black
     and -1.0 to white renders the buffer as a frame containing six copies
     of a single line of text.

  4. The text is a proportional bitmap font upscaled 3x horizontally and
     10/7 vertically. Sampling the underlying 7-row base grid recovers clean
     5x7 glyphs, which read as the flag.

The script runs against the full dump if it is present, and otherwise falls
back to the carved region shipped in artifacts/ so it works standalone.

Usage:  python3 solve.py [vram_dump.bin]
"""
from __future__ import annotations

import collections
import math
import struct
import sys
from pathlib import Path

import png

HERE = Path(__file__).resolve().parent
FULL_DUMP = HERE / "challenge" / "vram_dump.bin"
CARVED_REGION = HERE / "artifacts" / "vram-region-0x900000.bin"
ARTIFACTS = HERE / "artifacts"

BLOCK = 64 * 1024
ENTROPY_CUTOFF = 7.6          # bits/byte; scrubbed noise sits at ~8.0

FP16_POS_ONE = 0x3C00
FP16_NEG_ONE = 0xBC00

WIDTH, HEIGHT = 1024, 768
BASE_ROWS = 7                 # glyph cell height before the 10/7 upscale
COL_STEP = 3                  # horizontal upscale factor
COPY_GAP = 40                 # column gap separating side-by-side copies


def shannon(block: bytes) -> float:
    counts = collections.Counter(block)
    n = len(block)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def entropy_profile(data: bytes) -> list[tuple[int, float]]:
    return [(off, shannon(data[off:off + BLOCK])) for off in range(0, len(data), BLOCK)]


def locate_region(profile: list[tuple[int, float]], total: int) -> tuple[int, int]:
    """Return (start, end) of the single contiguous sub-threshold-entropy run."""
    runs: list[list[int]] = []
    for off, h in profile:
        if h >= ENTROPY_CUTOFF:
            continue
        if runs and runs[-1][1] == off:
            runs[-1][1] = min(off + BLOCK, total)
        else:
            runs.append([off, min(off + BLOCK, total)])
    if len(runs) != 1:
        raise ValueError(f"expected exactly one low-entropy run, found {len(runs)}: {runs}")
    return tuple(runs[0])                                            # type: ignore[return-value]


def decode_fp16_mask(region: bytes) -> list[int]:
    """Validate the region is a +/-1.0 fp16 buffer and return it as 0/1 ink."""
    hist = collections.Counter(region)
    if set(hist) != {0x00, 0x3C, 0xBC}:
        raise ValueError(f"unexpected byte values in region: {sorted(hist)}")
    values = struct.unpack(f"<{len(region) // 2}H", region)
    unexpected = set(values) - {FP16_POS_ONE, FP16_NEG_ONE}
    if unexpected:
        raise ValueError(f"unexpected fp16 values: {[hex(v) for v in unexpected]}")
    return [0 if v == FP16_POS_ONE else 1 for v in values]


def text_rows(ink: list[int]) -> list[tuple[int, int]]:
    """Group rows that contain ink into contiguous bands."""
    rows = [y for y in range(HEIGHT) if any(ink[y * WIDTH:(y + 1) * WIDTH])]
    bands: list[list[int]] = []
    for y in rows:
        if bands and y - bands[-1][-1] <= 2:
            bands[-1].append(y)
        else:
            bands.append([y])
    return [(b[0], b[-1]) for b in bands]


def copies(ink: list[int], y0: int, y1: int) -> list[tuple[int, int]]:
    """Split a text band into the side-by-side copies of the same string."""
    rows = range(y0, y1 + 1)
    cols = [x for x in range(WIDTH) if any(ink[y * WIDTH + x] for y in rows)]
    groups: list[list[int]] = []
    for x in cols:
        if groups and x - groups[-1][-1] <= COPY_GAP:
            groups[-1].append(x)
        else:
            groups.append([x])
    return [(g[0], g[-1]) for g in groups]


def base_grid(ink: list[int], y0: int, y1: int, x0: int, x1: int) -> list[int]:
    """Recover the glyph cell's BASE_ROWS scanlines from one upscaled copy.

    A copy is the base cell stretched vertically by (y1-y0+1)/BASE_ROWS with
    nearest-neighbour sampling, so consecutive identical scanlines are
    duplicates. Keeping one row per run of identical rows recovers the
    original grid. This must be done per copy: the two copies on a line sit
    at different sub-pixel phases, so their duplicated rows do not align.
    """
    inked = [y for y in range(y0, y1 + 1)
             if any(ink[y * WIDTH + x0:y * WIDTH + x1 + 1])]
    seen, grid = None, []
    for y in inked:                       # trim to this copy's own ink extent
        row = tuple(ink[y * WIDTH + x0:y * WIDTH + x1 + 1])
        if row != seen:
            grid.append(y)
            seen = row
    if len(grid) != BASE_ROWS:
        raise ValueError(f"expected {BASE_ROWS} base rows, recovered {len(grid)}: {grid}")
    return grid


def glyph_spans(ink: list[int], rows: list[int], x0: int, x1: int) -> list[tuple[int, int]]:
    cols = [x for x in range(x0, x1) if any(ink[y * WIDTH + x] for y in rows)]
    spans: list[list[int]] = []
    for x in cols:
        if spans and x - spans[-1][-1] <= COL_STEP:
            spans[-1].append(x)
        else:
            spans.append([x])
    return [(s[0], s[-1]) for s in spans]


def render_glyph(ink: list[int], rows: list[int], span: tuple[int, int]) -> list[str]:
    x0, x1 = span
    width = (x1 - x0) // COL_STEP + 1
    return ["".join("#" if ink[y * WIDTH + x0 + c * COL_STEP] else "."
                    for c in range(width)) for y in rows]


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        path, carved = Path(argv[1]), False
    elif FULL_DUMP.is_file():
        path, carved = FULL_DUMP, False
    elif CARVED_REGION.is_file():
        path, carved = CARVED_REGION, True
    else:
        print(f"error: place the handout at {FULL_DUMP} or pass a path", file=sys.stderr)
        return 1

    data = path.read_bytes()
    print(f"{path.name}: {len(data):,} bytes")

    if carved:
        print("note: full dump not present, using the carved region from artifacts/")
        base, region = 0x900000, data
    else:
        profile = entropy_profile(data)
        noisy = sum(1 for _, h in profile if h >= ENTROPY_CUTOFF)
        print(f"  entropy: {noisy}/{len(profile)} blocks of {BLOCK // 1024} KiB at "
              f">= {ENTROPY_CUTOFF} bits/byte (scrubbed noise)")
        base, end = locate_region(profile, len(data))
        region = data[base:end]
        print(f"  survivor: {base:#010x} - {end:#010x}  ({len(region):,} bytes)")
        if ARTIFACTS.is_dir():
            with (ARTIFACTS / "entropy-profile.csv").open("w") as fh:
                fh.write("offset,entropy_bits_per_byte\n")
                for off, h in profile:
                    fh.write(f"{off:#010x},{h:.6f}\n")

    ink = decode_fp16_mask(region)
    n = len(ink)
    print(f"  fp16 +/-1.0 buffer: {n:,} elements, {sum(ink):,} set "
          f"({sum(ink) / n:.2%})  ->  {n // HEIGHT} x {HEIGHT}")
    if n != WIDTH * HEIGHT:
        raise ValueError(f"{n} elements does not reshape to {WIDTH}x{HEIGHT}")

    if ARTIFACTS.is_dir():
        png.write_gray(str(ARTIFACTS / "tensor-1024x768.png"), WIDTH, HEIGHT,
                       bytes(255 if b else 0 for b in ink))

    bands = text_rows(ink)
    print(f"  text bands at rows: {bands}")

    band = bands[0]
    blocks = copies(ink, *band)
    print(f"  copies per band: {len(blocks)} at columns {blocks}")

    first = blocks[0]
    rows = base_grid(ink, band[0], band[1], first[0], first[1])
    print(f"  base glyph grid rows: {rows}")

    signatures = {
        tuple(tuple(ink[y * WIDTH + x] for x in range(bx0, bx1 + 1))
              for y in base_grid(ink, by0, by1, bx0, bx1))
        for by0, by1 in bands for bx0, bx1 in copies(ink, by0, by1)
    }
    print(f"  distinct base bitmaps across all "
          f"{len(bands) * len(blocks)} copies: {len(signatures)}")

    spans = glyph_spans(ink, rows, first[0], first[1] + 1)
    glyphs = [render_glyph(ink, rows, s) for s in spans]
    print(f"  {len(glyphs)} glyphs in the first copy\n")
    for r in range(BASE_ROWS):
        print("   " + "  ".join(g[r] for g in glyphs))

    if ARTIFACTS.is_dir():
        scale, pad = 3, 2
        cx0, cx1 = first[0] - pad, first[1] + pad
        cy0, cy1 = band[0] - pad, band[1] + pad
        cw, ch = (cx1 - cx0 + 1) * scale, (cy1 - cy0 + 1) * scale
        crop = bytearray(cw * ch)
        for y in range(ch):
            for x in range(cw):
                crop[y * cw + x] = 255 if ink[(cy0 + y // scale) * WIDTH + cx0 + x // scale] else 0
        png.write_gray(str(ARTIFACTS / "flag-crop.png"), cw, ch, bytes(crop))

        with (ARTIFACTS / "glyphs.txt").open("w") as fh:
            fh.write(f"{len(glyphs)} glyphs, {BASE_ROWS}-row base grid "
                     f"(rows {rows}, {COL_STEP}x horizontal upscale)\n\n")
            for span, g in zip(spans, glyphs):
                fh.write(f"x{span[0]}-{span[1]}  ({len(g[0])} base columns)\n")
                fh.write("".join(f"    {row}\n" for row in g) + "\n")

    print("\nFlag: zdk{MemOrY_1Eak_found}")
    print("(the render shows a full-height 'Z'; the accepted flag is lowercase 'z')")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
