# Ghost in the GPU

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | neerajcodz |
| Points | 131 |
| Solves at time of solving | 95 |
| Flag | `zdk{MemOrY_1Eak_found}` |

> The inference job crashed and left behind a raw VRAM dump. The accelerator
> was scrubbed, but the memory capture survived.

## Executive Summary

`vram_dump.bin` is a 32 MiB raw VRAM capture. The device was scrubbed with
random bytes, so the file defeats every signature- and string-based tool: it has
no recognisable header, `strings` yields nothing, and 488 of its 512 64 KiB
blocks sit at essentially maximum Shannon entropy.

The scrub was not complete. A **single contiguous 1.5 MiB region at
`0x00900000`** survives, and it is trivially separable by entropy: it contains
only three distinct byte values against a background of uniform noise.

That region is a leftover **fp16 inference buffer**. Read as little-endian
`uint16` it consists exclusively of `0x3C00` and `0xBC00` — IEEE-754 half
precision for `+1.0` and `-1.0`. It is a two-valued mask tensor, not real
activations, and 786,432 elements reshape exactly to **1024 × 768**. Rendering
`-1.0` as ink produces a frame containing six identical copies of one line of
text: the flag.

The supplied [solver](solve.py) performs the entropy scan, carves the region,
validates the fp16 encoding, reshapes and renders the frame, and mechanically
recovers the underlying 5×7 glyph bitmaps rather than relying on a visual read.

```
zdk{MemOrY_1Eak_found}
```

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/README.md`](challenge/README.md) | Handout hashes and why the 30.5 MiB archive is not committed | — |
| [`solve.py`](solve.py) | Standalone solver, no third-party dependencies | — |
| [`png.py`](png.py) | Minimal greyscale PNG writer (stdlib only) | — |
| [`artifacts/vram-region-0x900000.bin`](artifacts/vram-region-0x900000.bin) | The carved 1.5 MiB fp16 allocation | `b3d7a4dca63b0f0d96681fd038c702c7192da150244d51d90f57f28c901e2d41` |
| [`artifacts/tensor-1024x768.png`](artifacts/tensor-1024x768.png) | The tensor rendered as a 1024×768 frame | — |
| [`artifacts/flag-crop.png`](artifacts/flag-crop.png) | 3× crop of the first copy of the text | — |
| [`artifacts/glyphs.txt`](artifacts/glyphs.txt) | All 22 recovered 5×7 base bitmaps | — |
| [`artifacts/entropy-profile.csv`](artifacts/entropy-profile.csv) | Per-64 KiB Shannon entropy across the dump | — |

The original `vram_dump.bin` has SHA-256
`efafbbcbdeab0f6b6d4f07c1ab74615e60f2ff815a5db067ebeda43f801a91b4`.

## 1. Initial Triage

The handout contains one file, and nothing recognises it:

```console
$ unzip -l ghost-in-the-gpu.zip
  Length      Name
---------     ----
 33554432     vram_dump.bin

$ file vram_dump.bin
vram_dump.bin: data

$ xxd vram_dump.bin | head -3
00000000: 4fe3 9492 2f6a d9c6 f586 f34e 3bbd ad0e  O.../j.....N;...
00000010: 3e8f 25ef 6f63 8dcd 4c02 4a6c a867 e74a  >.%.oc..L.Jl.g.J
00000020: 8b52 bba2 1c43 dfbe 3e0e 7ec2 c496 cd66  .R...C..>.~....f

$ strings -n 8 vram_dump.bin | head -3
^1i#L&4l
mWjPz|@wG8
?Um g"^H
```

The `strings` output is the important negative result: those are chance
alphanumeric runs of the kind uniform random bytes produce constantly, not
text. Likewise, scanning for file signatures (`PNG`, `JPEG`, `ELF`, `PK\x03\x04`,
`\x93NUMPY`, `GGUF`, …) returns only coincidental two- and three-byte hits
scattered uniformly through the file — exactly the density expected by chance in
32 MiB of noise, with no accompanying structure at any hit.

Signature carving is therefore the wrong tool. The brief says the accelerator
was *scrubbed* but the capture *survived*, which reframes the problem: do not
look for a known format, look for **whatever is not noise**.

## 2. Entropy Localisation

Random filler has ~8.0 bits/byte of Shannon entropy. Any real structure —
tensor data, a framebuffer, a page table — has measurably less. Profiling the
dump in 64 KiB blocks isolates the survivor immediately:

```console
$ python3 solve.py
vram_dump.bin: 33,554,432 bytes
  entropy: 488/512 blocks of 64 KiB at >= 7.6 bits/byte (scrubbed noise)
  survivor: 0x00900000 - 0x00a80000  (1,572,864 bytes)
```

488 of 512 blocks are indistinguishable from random. The remaining 24 form one
contiguous, page-aligned 1.5 MiB run. Re-running the scan at 4 KiB granularity
returns the identical boundaries, confirming the region is a single clean
allocation rather than a smeared remnant:

```
0x00900000 - 0x00a80000   (1,572,864 bytes)
```

This is the whole of the discovery step. Everything after it is decoding.

## 3. Identifying the Encoding

The region's byte histogram has only three entries, and exactly half of all
bytes are zero:

```
0x00 -> 786,432    (50.00%)
0x3c -> 778,683
0xbc ->   7,749

first bytes:  00 3c 00 3c 00 3c 00 3c 00 3c 00 3c ...
```

A strictly alternating `00 XX` pattern with a two-valued high byte is a 16-bit
type whose values come from a set of two. Read little-endian:

| Halfword | IEEE-754 binary16 | Count |
| --- | --- | --- |
| `0x3C00` | `+1.0` | 778,683 |
| `0xBC00` | `-1.0` | 7,749 |

sign `0`/`1`, exponent `01111` (biased 15 → 2⁰), mantissa `0` — textbook fp16
`±1.0`. The buffer is therefore a **half-precision tensor** holding a two-valued
mask: consistent with the "inference job" framing, and the reason no numeric
analysis is needed. Only 0.99% of elements are `-1.0`, which is the shape of
sparse foreground on a uniform background.

The solver asserts this rather than assuming it — it rejects the region if any
halfword outside `{0x3C00, 0xBC00}` appears.

## 4. Reshaping the Tensor

```
1,572,864 bytes / 2 = 786,432 elements
786,432 = 1024 x 768
```

786,432 factors many ways (`512×1536`, `2048×384`, …), so the correct geometry
was determined empirically: rendering at each candidate width, only **1024 × 768**
produces coherent horizontal text. It is also the only candidate that is a
standard display resolution, which is the natural shape for a framebuffer-like
allocation.

Mapping `+1.0` → black and `-1.0` → white gives
[`artifacts/tensor-1024x768.png`](artifacts/tensor-1024x768.png): a 1024×768
frame carrying the same line of text six times, laid out two columns by three
rows.

## 5. Reading the Text Mechanically

The text is legible by eye, but one character is genuinely ambiguous at a glance
(see §6), so the glyphs were recovered as bitmaps rather than read off the
image.

The rendering is a small bitmap font upscaled non-uniformly: strokes are 3 px
wide horizontally, and each 10- or 11-row band collapses to **7 distinct
scanlines**, i.e. a 7-row cell nearest-neighbour stretched by 10/7. Recovering
the base grid means keeping one row per run of identical scanlines.

One subtlety matters here. The two copies on a line sit at *different sub-pixel
phases* of that 10/7 stretch — the left copy duplicates rows (124,125), (127,128),
(130,131) while the right duplicates (122,123), (125,126), (128,129), (131,132).
Deduplicating across the full image width therefore finds no duplicates at all.
The de-scaling has to be done **per copy**, over that copy's own column range and
its own ink extent:

```console
  text bands at rows: [(122, 132), (378, 388), (634, 644)]
  copies per band: 2 at columns [(59, 451), (571, 963)]
  base glyph grid rows: [123, 124, 126, 127, 129, 130, 132]
  distinct base bitmaps across all 6 copies: 1
  22 glyphs in the first copy
```

`distinct base bitmaps across all 6 copies: 1` is worth stating explicitly: all
six copies collapse to one identical bitmap, so there is no second message
hidden in one of them.

Sampling the 7 base rows at every third column yields clean 5×7 glyphs:

```
#####  ....#  #....  ..##.  #...#  .....  .....  .###.  .....  #...#  .....
....#  ....#  #..#.  .#...  ##.##  .###.  ##.##  #...#  #.##.  #...#  .....
...#.  .##.#  #.#..  .#...  #.#.#  #...#  #.#.#  #...#  ##..#  .#.#.  .....
..#..  #..##  ##...  #....  #.#.#  #####  #.#.#  #...#  #....  ..#..  .....
.#...  #...#  #.#..  .#...  #...#  #....  #.#.#  #...#  #....  ..#..  .....
#....  #..##  #..#.  .#...  #...#  #...#  #.#.#  #...#  #....  ..#..  .....
#####  .##.#  #...#  ..##.  #...#  .###.  #.#.#  .###.  #....  ..#..  #####
  Z      d      k      {      M      e      m      O      r      Y      _

.#...  #####  .....  #....  .....  ..##.  .....  .....  .....  ....#  ##...
##...  #....  .###.  #..#.  .....  .#..#  .###.  #...#  #.##.  ....#  ..#..
.#...  #....  ....#  #.#..  .....  .#...  #...#  #...#  ##..#  .##.#  ..#..
.#...  ####.  .####  ##...  .....  ###..  #...#  #...#  #...#  #..##  ...#.
.#...  #....  #...#  #.#..  .....  .#...  #...#  #...#  #...#  #...#  ..#..
.#...  #....  #..##  #..#.  .....  .#...  #...#  #..##  #...#  #..##  ..#..
###..  #####  .##.#  #...#  #####  .#...  .###.  .##.#  #...#  .##.#  ##...
  1      E      a      k      _      f      o      u      n      d      }
```

Full bitmaps for all 22 glyphs are in
[`artifacts/glyphs.txt`](artifacts/glyphs.txt).

## 6. The Leading Character

The render's first glyph is **full height** — seven rows — and this font has a
genuine lowercase set, which it uses elsewhere in the same string:

| Pair | Uppercase | Lowercase |
| --- | --- | --- |
| `M` / `m` | 7 rows, pointed middle | 6 rows, two humps |
| `O` / `o` | 7 rows | 6 rows |
| `E` / `e` | 7 rows | 6 rows |

Every x-height letter in the string (`e m r o u n a`) has a blank top row;
every full-height one (`M O Y E d k f`) does not. A lowercase `z` has no
ascender and should have rendered at x-height. It did not, so read literally the
image says `Zdk{…}`.

**The accepted flag is nonetheless lowercase `zdk{MemOrY_1Eak_found}`**, matching
the platform prefix used by every other challenge in this CTF. The most likely
explanation is a glyph-table fallback: the lowercase letters that do appear are
exactly the ten the rest of the string needs (`d k e m r a f o u n`) and no more,
so a table lacking a lowercase `z` would silently substitute the uppercase form.

Everything after the `{` is unambiguous — the ambiguity is confined to that one
character, and it resolves in favour of the platform convention.

```
zdk{MemOrY_1Eak_found}
```

## 7. Reproducing

The 30.5 MiB handout is not committed (see
[`challenge/README.md`](challenge/README.md)); the carved 1.5 MiB region is, and
the solver falls back to it automatically.

```console
$ cd Forensics/ghost-in-the-gpu
$ python3 solve.py
vram-region-0x900000.bin: 1,572,864 bytes
note: full dump not present, using the carved region from artifacts/
  fp16 +/-1.0 buffer: 786,432 elements, 7,749 set (0.99%)  ->  1024 x 768
  text bands at rows: [(122, 132), (378, 388), (634, 644)]
  copies per band: 2 at columns [(59, 451), (571, 963)]
  base glyph grid rows: [123, 124, 126, 127, 129, 130, 132]
  distinct base bitmaps across all 6 copies: 1
  22 glyphs in the first copy
  ...
Flag: zdk{MemOrY_1Eak_found}
```

To run the complete pipeline including the entropy scan and carve, drop
`vram_dump.bin` into `challenge/` first. The solver requires only the Python 3
standard library.

## Lessons

- **When signature carving finds nothing, invert the question.** The dump had no
  header to find; the payload was identifiable purely as *the part that is not
  random*. An entropy profile located it in one pass.
- **A byte histogram identifies numeric types.** Three distinct byte values with
  exactly 50% zeros is a 16-bit type; `0x3C00`/`0xBC00` is fp16 `±1.0` on sight,
  and immediately explains the buffer's role as a mask.
- **Prefer factorisation plus a render sweep over guessing geometry.** Six
  candidate shapes cost seconds to render and only one produced readable text.
- **De-scale per instance, not globally.** The two copies of the text sat at
  different sub-pixel phases; a global duplicate-row search silently found
  nothing and would have derailed the glyph recovery.
- **Recover glyphs as bitmaps when a character matters.** Reading the image by
  eye would have hidden the fact that the leading `Z` is genuinely full height —
  a detail worth knowing about before submitting.
