# Undertow

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | ant1v3n0m |
| Points | 321 |
| Solves at time of solving | 11 |
| Flag | `zdk{4_ST4L3_CheckP0INt_s4nK_BeLOW_The_pOInTER_gUarD}` |

> i dont even know anymore but checkpointing is hard

## Executive Summary

Undertow is a stripped x86-64 checkpoint service built against the supplied
Ubuntu glibc 2.39. It implements its own pointer encoding, context save and
restore routines, integrity hash, three-list record allocator, and two-entry
quarantine. The process also installs a tight seccomp filter before accepting
normal commands.

The intended attack combines four separate weaknesses:

1. A diagnostic command exposes one linear equation in a fixed, secret
   128-bit `UNDERTOW_SEAL`. Each process has a random session token, so opening
   enough connections produces 128 independent equations. Gaussian
   elimination over GF(2) recovers the complete seal.
2. The inspect command discloses encoded pointers to the checkpoint-save
   routine and a controlled scratch mapping. The recovered seal derives the
   context codec, allowing both pointers to be decoded and defeating PIE and
   scratch-map ASLR.
3. Committing a checkpoint leaves the global current-checkpoint pointer intact
   while placing the same record in a delayed quarantine. Carefully chosen
   allocator churn moves that record into the list used by the snapshot
   command. Snapshot then clears and overwrites the record through a second
   alias, turning the original pointer into an attacker-controlled stale
   checkpoint.
4. Because the seal is known, the exploit can encode a forged stack pointer
   and instruction pointer and recompute the checkpoint hash. Restoring that
   record starts a ROP chain in the scratch mapping. Stage one leaks the GOT to
   recover libc and receives stage two. Stage two uses `setcontext+0x20` and
   the libc syscall wrapper to list the pre-opened flag directory, open its
   randomized filename with the filter-approved `openat2` arguments, and send
   the flag.

The supplied [solver](solve.py) performs the entire attack with only Python's
standard library. It can either recover the seal automatically or accept a
previously recovered value with `--seal`.

```text
many TLS sessions               final TLS session
-----------------               -----------------
session token                   create checkpoint
     |                          inspect encoded pointers
CRC-gated oracle                upload stage one
     |                          commit + allocator churn
one GF(2) row                   snapshot-overwrite checkpoint
     |                          restore forged context
Gaussian elimination ---------> GOT leak -> libc base
128-bit seal                    stage two -> getdents/openat2/read/write
```

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_undertow.tar.gz`](challenge/pwn_undertow.tar.gz) | Original challenge handout | `c1f6381f9f028261a5bdb8b06fa0bbdbec6bce3260434478350e2d7308e3ccaa` |
| [`challenge/undertow`](challenge/undertow) | Stripped challenge executable | `8329a70368c28fbda117990295e7a8c5ac80a74facdf31c53eb419430d2dbfc0` |
| [`challenge/libc.so.6`](challenge/libc.so.6) | Supplied Ubuntu glibc 2.39 | `8db37cf3f2169f59a0f07ef1fea308c35656668c64c8ff294e1860f4121eb161` |
| [`challenge/ld-linux-x86-64.so.2`](challenge/ld-linux-x86-64.so.2) | Supplied dynamic loader | `cd4df4f3c7b83673d61189bf2eaebd33ca4f2853ab9772b8a25e025ef99b1e81` |
| [`solve.py`](solve.py) | Dependency-free end-to-end remote exploit | `332dc93fc6930ebbc7b77293ab0027f5545333b47f90a38341e79242e3326141` |
| [`verify_offline.py`](verify_offline.py) | Offline seal, pointer, route, and checkpoint verification | `80a38bac45684c443ba7b8f0b4119c827ff1666a890777bfbbd77a98ffbc4a0e` |
| [`artifacts/protocol-and-offsets.txt`](artifacts/protocol-and-offsets.txt) | Protocol map, formulas, structures, offsets, and syscall plan | `a29652cf3503d8be97ed32e230c9f6b3b68220105130cc073f6514afebb169cf` |
| [`artifacts/decompiled.c`](artifacts/decompiled.c) | Ghidra decompilation used during analysis | `89a0c5cadfda0c0a7547104a1c79b3e3cd62575b2552bb93a484bc1b5f608db6` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful live exploit transcript | `13596093480b8a99c10ab59c282dceeeb5fda6041d92bf2d3e7564f75d409658` |

## 1. Initial Triage

The handout contains the executable and its exact runtime:

```console
$ tar -tzvf pwn_undertow.tar.gz
-rwxrwxrwx ... pwn_undertow/ld-linux-x86-64.so.2
-rwxrwxrwx ... pwn_undertow/libc.so.6
-rwxrwxrwx ... pwn_undertow/undertow
```

Basic file inspection shows a small, stripped PIE executable:

```console
$ file undertow
undertow: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2, stripped

$ strings libc.so.6 | grep 'GNU C Library' | head -1
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.8) stable release version 2.39.
```

`rabin2 -I undertow` reports the relevant hardening:

| Mitigation | State | Consequence |
| --- | --- | --- |
| Full RELRO | Enabled | The GOT can be leaked but not overwritten |
| Stack canary | Enabled | Ordinary stack corruption is unattractive |
| NX | Enabled | Scratch data cannot execute directly |
| PIE | Enabled | A code disclosure is required |
| Symbols | Stripped | Protocol handlers and helpers must be reconstructed |

The visible strings are almost entirely numeric status messages. The banner
from a fresh connection gives the first useful map:

```text
100 6
101 5b93106e9632c1c8
901 1 2 3 4 5 6 7 8 9
900
```

`101` includes a new random 64-bit session token. `900` marks the end of a
response and the point at which another command may be sent.

## 2. Reconstructing the Command Protocol

The jump table at PIE offset `0x30d4` maps inputs 0 through 9 to handlers. By
following each target and matching accesses to the strings in `.rodata`, the
normal protocol is:

| Command | Success sequence | Reconstructed operation |
| --- | --- | --- |
| `1` | `110` | Allocate and save a new checkpoint |
| `2` | `210 <hex>`, `211 <hex>` | Inspect encoded function and scratch pointers |
| `3` | `310` | Commit the active checkpoint to quarantine |
| `4` | `410`, 0x500 raw bytes, `411` | Allocate and overwrite a snapshot record |
| `5` | `510`, size, `511`, raw bytes, `512` | Upload at most 0x1000 bytes to scratch |
| `6` | `610` | Validate and restore the committed checkpoint |
| `7` | connection closes | Exit |
| `8` | `810`, CRC, `812 <bit>` | Query one seal-oracle bit, then exit |
| `9` | `910`, byte, `911` | Churn one allocator record through quarantine |

The `5xx` upload handshake is worth recording exactly. `591` is the error
status when initialization is unavailable; it is not a prompt. A successful
upload is:

```text
client: 5
server: 510
client: 4096
server: 511
client: <4096 raw bytes>
server: 512
server: 901 ...
server: 900
```

## 3. Process Initialization

The initialization path establishes all of the state that later appears in
the exploit.

### 3.1 The fixed 128-bit seal

The process reads `UNDERTOW_SEAL` as exactly 32 hexadecimal characters, parses
it into 16 bytes, and immediately removes the environment variable. Let the
little-endian halves be `lo` and `hi`. Four 64-bit values are derived:

```text
pointer_add = rol64(lo + hi + 0x3ad7f16c805e294b, 31)
pointer_xor = rol64(lo ^ hi ^ 0x91e4b37ac6205df8, 23)
context_add = rol64(hi ^ 0xb47c19e25a603df8, 29)
context_xor = lo ^ 0x6d8f2a41c395e7b0
```

The first pair protects allocator free-list pointers. The second pair protects
saved `rsp`, saved `rip`, and both addresses disclosed by command 2.

### 3.2 Flag directory and scratch mappings

The program obtains `UNDERTOW_FLAG_DIR`, opens it with `O_DIRECTORY`, moves the
descriptor to fd 9 with `dup2`, closes the original descriptor when needed,
and removes that environment variable.

It then creates a randomized fixed-address 0x4000-byte scratch mapping in the
`0x200000000000` region. The first 0x3000 bytes remain writable. The last page
is initialized and changed to read-only:

```c
struct open_how *how = scratch + 0x3f00;
how->flags = 0;
how->mode = 0;
how->resolve = 0x0a;  // RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
mprotect(scratch + 0x3000, 0x1000, PROT_READ);
```

A second randomized mapping backs twelve linked allocator records. Each useful
record is 0x500 bytes; the initialization loop spaces records by 0x510 and
distributes them among three encoded free lists.

### 3.3 Seccomp

After the first checkpoint is created, the binary installs a 25-instruction
classic BPF seccomp filter. The allowlist is intentionally narrow:

| Syscall | Number | Constraint |
| --- | ---: | --- |
| `read` | 0 | Allowed |
| `write` | 1 | Allowed |
| `exit` | 60 | Allowed |
| `getdents64` | 217 | Allowed |
| `exit_group` | 231 | Allowed |
| `openat2` | 437 | `dirfd=9`, `how=scratch+0x3f00`, `size=24` |

Everything else terminates the process. In particular, `execve`, `mprotect`,
ordinary `openat`, and `rt_sigprocmask` are unavailable after initialization.
A shell is neither possible nor necessary.

## 4. Recovering `UNDERTOW_SEAL`

Command 8 initially looks like a weak health-check endpoint. It is the first
major vulnerability.

### 4.1 Passing the session gate

After emitting `810`, the handler expects a 16-bit integer. It computes a
CRC-16 over the eight little-endian bytes of the displayed session token:

```text
initial state = 0x1d0f
polynomial    = 0x1021
input         = p64(session)
```

An incorrect value prints `892` and exits. The CRC is not secret because the
session token is already in the `101` line. For example:

```text
session = 5b93106e9632c1c8
CRC     = 6bc8
```

### 4.2 The one-bit equation

For a valid CRC, the process deterministically expands the session token into
two 64-bit masks. The mixing function is SplitMix64 without the initial state
increment:

```python
def splitmix(x):
    x ^= x >> 30
    x *= 0xbf58476d1ce4e5b9
    x ^= x >> 27
    x *= 0x94d049bb133111eb
    return x ^ (x >> 31)

mask_lo = splitmix((session ^ 0x73d5a9c41f286be0)
                   + 0x9e3779b97f4a7c15)
mask_hi = splitmix((rol64(session, 23) ^ 0xa6e87c159bd2034f)
                   + 0x9e3779b97f4a7c15)
```

All operations are modulo 2^64. The returned bit is:

```text
result = parity(mask_lo & seal_lo) XOR parity(mask_hi & seal_hi)
```

Equivalently, concatenate the masks and seal into 128-bit integers:

```text
parity(mask & seal) = result
```

This is one linear equation over GF(2), not a cryptographic predicate. The
session changes on every connection while the environment seal remains fixed,
so every connection supplies a new row of the same 128-variable system.

### 4.3 Gaussian elimination

The solver stores one row for each highest set bit. To insert a new row, it
XORs away existing pivots until either the row becomes dependent or creates a
new pivot. Once the matrix reaches rank 128, increasing-pivot back-substitution
recovers the unique seal.

Oracle command 8 exits after returning `812`, so each query intentionally uses
one TLS connection. Two worker threads are enough to gather the rows quickly
without overwhelming the service.

For the captured challenge instance, the recovered bytes were:

```text
UNDERTOW_SEAL = 4eaf20afbf05b2f1805d0261950df065
```

The derived keys are:

```text
pointer_add = 0xc8409b0cc93d0260
pointer_xor = 0xa80401579b02d35d
context_add = 0xe76c4c0f1a31828e
context_xor = 0x9c3d2ffe6cb548fe
```

## 5. Turning Command 2 into ASLR Disclosures

After command 1 creates a checkpoint, command 2 returns two protected
addresses:

```text
210 96ab934719a35615
211 8932b264ad515615
```

Both use the context-pointer codec:

```text
encode(p) = rol64(p XOR context_xor, 13) + context_add
decode(e) = ror64(e - context_add, 13) XOR context_xor
```

Decoding the example values gives:

```text
decoded 210 = 0x5604550ab370 = PIE + 0x2370
PIE base    = 0x5604550a9000

decoded 211 = 0x21cd5e19d000 = scratch base
```

PIE offset `0x2370` is the custom checkpoint-save routine. Both decoded
addresses are page-aligned after subtracting that offset, giving useful sanity
checks before the exploit mutates allocator state.

## 6. The Custom Checkpoint Format

Each allocator record is 0x500 bytes. The context and integrity fields occupy
the following offsets:

```text
+0x40  rbx
+0x48  rbp
+0x50  r12
+0x58  r13
+0x60  r14
+0x68  r15
+0x70  encoded rsp
+0x78  encoded rip
+0x80  integrity hash
```

The save routine at PIE offset `0x2370` stores the six callee-saved registers,
then protects its two control-flow values:

```text
record->saved_rsp = encode_context(rsp + 8)
record->saved_rip = encode_context(*(uint64_t *)rsp)
```

The restore routine at `0x23c0` reverses those operations, restores the six
registers, assigns the decoded stack pointer to `rsp`, and jumps to decoded
`rip`.

Before restore, command 6 recomputes a keyed hash over the eight qwords from
`+0x40` through `+0x78`. Reconstructed pseudocode is:

```python
state = context_xor ^ 0x4f17b2c39a68de05
stream = context_add

for i, qword in enumerate(qwords(record[0x40:0x80])):
    stream += 0x6a09e667f3bcc909
    state ^= qword + stream
    state = rol64(state, (i * 7) % 47 + 9)
    state *= 0x9e3779b185ebca87
    state ^= state >> 29

hash = rol64(context_add, 17) ^ state ^ 0xc2b2ae3d27d4eb4f
```

All arithmetic is modulo 2^64. This protects against blind record corruption,
but it does not provide integrity after the key material has been leaked by
the linear oracle.

## 7. The Three Lists and Two-Entry Quarantine

The second major component is the custom allocator.

### 7.1 Encoded free-list pointers

There are three free-list heads. A record pointer is stored as:

```text
encoded = rol64(pointer XOR pointer_xor, 7) + pointer_add
```

Popping a record decodes the selected head, replaces the head with the encoded
next pointer from the record, and clears the complete 0x500-byte record.

### 7.2 Delayed release

Records are not returned directly to a free list. The function at `0x2180`
maintains a two-entry FIFO. Every queued record carries a destination-list
tag. The first two calls only fill the FIFO. On every subsequent call, the
oldest record is linked into its tagged free list while the new record enters
the FIFO.

This is a small quarantine intended to prevent immediate reuse of checkpoint
objects.

### 7.3 List selection

Creating and committing a checkpoint uses:

```text
checkpoint_list = (seal[2] XOR 0x552) mod 3
```

Snapshot command 4 uses a different selector:

```text
snapshot_list = (seal[2] XOR 0x55a) mod 3
```

Command 9 accepts one byte `v`, selects a source list, fills part of the
allocated record with `v`, and queues it with a destination tag:

```text
mixed       = (v * 0xc5 + seal[4]) & 0xff
source      = mixed mod 3
destination = (seal[5] + floor(mixed / 3)) mod 3
```

Because the seal is now known, command 9 is a deterministic record-routing
primitive.

## 8. Root Cause: Snapshot Reclaims a Live Checkpoint

Command 3 commits the current checkpoint by placing its record in quarantine
and clearing only the active-state flag. Crucially, the global current pointer
continues to reference that record because command 6 needs it later.

The allocator does not treat this persistent pointer as ownership. Once the
quarantine releases the record, another operation may allocate it while the
current pointer remains live.

For the captured seal:

```text
checkpoint_list = 2
snapshot_list   = 1

command-9 input 0: source 2, destination 2
command-9 input 5: source 2, destination 1
```

The solver searches all 256 byte values for one whose source is the checkpoint
list and whose destination is the snapshot list. It finds `5`, producing the
route `[0, 0, 5, 0, 0]`.

The complete state transition is:

| Step | Operation | Effect on the checkpoint record |
| ---: | --- | --- |
| 1 | Commit command 3 | Enters the two-entry quarantine, current pointer retained |
| 2 | Churn `0` | Adds one ordinary record behind it |
| 3 | Churn `0` | Evicts checkpoint into free list 2 |
| 4 | Churn `5` | Reclaims checkpoint from list 2 and tags it for list 1 |
| 5 | Churn `0` | Advances the checkpoint through quarantine |
| 6 | Churn `0` | Evicts checkpoint into free list 1 |
| 7 | Snapshot command 4 | Pops that record from list 1 and reads 0x500 attacker bytes into it |

After step 7, both globals point to the same physical record:

```text
current_checkpoint ----+
                       +---- attacker-controlled 0x500-byte record
snapshot_pointer ------+
```

Command 6 validates and restores through `current_checkpoint`, unaware that
snapshot has cleared and overwritten the object. This is a stale-reference
use-after-reallocation rather than a conventional glibc heap UAF.

## 9. Forging the Restore Context

The exploit uploads stage one to `scratch` before disturbing the checkpoint.
It then builds an otherwise zeroed 0x500-byte replacement record:

```python
record[0x70] = encode_context(scratch)
record[0x78] = encode_context(PIE + 0x142a)  # pop rdi; ret
record[0x80] = checkpoint_hash(record)
```

For the example disclosure, those values are:

```text
encoded rsp = 0x8932b264ad515615
encoded rip = 0x96ab934717cc1615
hash        = 0xb15fe2ceefbd557a
```

When command 6 restores the forged record, execution begins at an unaligned
`pop rdi; ret` gadget with `rsp=scratch`. The first uploaded qword is therefore
the first ROP argument.

## 10. Stage One: Leak libc and Receive Stage Two

The small executable still contains enough gadgets in its main-function
epilogue and integer parser:

| PIE offset | Gadget or function |
| ---: | --- |
| `0x1428` | `pop rsi; pop r15; ret` |
| `0x142a` | `pop rdi; ret` |
| `0x20f9` | `pop rsp; pop r13; ret` |
| `0x2130` | exact-length read helper |
| `0x2320` | exact-length write helper |
| `0x4f30` | first PLT GOT entry |

Stage one performs three operations:

```text
write_exact(PIE + 0x4f30, 0xa8)
read_exact(scratch + 0x1000, 0x1000)
pivot rsp to scratch + 0x1000
```

The 0xa8-byte disclosure covers every PLT GOT entry. `write@GOT` is at
`PIE+0x4f50`, offset 0x20 in the leak. In the supplied libc:

```text
write     = libc + 0x11c690
setcontext= libc + 0x04a960
syscall   = libc + 0x127370
```

Therefore:

```text
libc_base = leaked_write - 0x11c690
```

The exploit computes stage two only after receiving this disclosure and sends
it through the stage-one `read_exact` call.

## 11. Stage Two Under Seccomp

### 11.1 Why use `setcontext+0x20`

The normal glibc 2.39 `setcontext` entry begins with syscall 14,
`rt_sigprocmask`:

```asm
setcontext:
    push rdi
    ...
    mov eax, 14
    syscall
    pop rdx
    ... restore registers from [rdx] ...
```

Seccomp does not allow syscall 14. The useful internal entry is exactly 0x20
bytes after the function start:

```asm
setcontext+0x20:
    pop rdx
    cmp rax, -0xfff
    ...
    mov rsp, [rdx+0xa0]
    ...
    return to [rdx+0xa8]
```

Returning to `setcontext+0x20` with a context pointer as the next stack qword
skips the forbidden syscall and restores a controlled register set. The CET
branch is not active in the service, so the ordinary restore path applies.

### 11.2 Calling arbitrary allowed syscalls

The libc `syscall` wrapper uses the normal function-call ABI and rearranges it
into the Linux syscall ABI:

```asm
mov rax, rdi       ; syscall number
mov rdi, rsi       ; argument 1
mov rsi, rdx       ; argument 2
mov rdx, rcx       ; argument 3
mov r10, r8        ; argument 4
mov r8,  r9        ; argument 5
mov r9, [rsp+8]    ; argument 6
syscall
ret
```

Each fake context sets its restored return address to this wrapper and its
stack to another small chain. When the wrapper returns, that chain invokes
`setcontext+0x20` on the next fake context.

### 11.3 Finding the randomized flag filename

The first context invokes:

```c
getdents64(9, scratch + 0x2000, 0x400);
```

The following ROP chain sends the entire zero-padded directory buffer to the
client. The solver parses Linux `dirent64` records and chooses the non-dot entry
containing `flag`. In the recorded run:

```text
['.', '..', 'flag_de56852d']
```

It writes that null-terminated name back into `scratch+0x2800`.

### 11.4 Opening and returning the flag

The remaining contexts execute only filter-approved calls:

```c
openat2(9, scratch + 0x2800, scratch + 0x3f00, 24);
read(3, scratch + 0x2400, 0x100);
write(1, scratch + 0x2400, 0x100);
```

No other descriptors are opened after initialization, so successful
`openat2` returns fd 3. The final write sends the flag and zero padding to the
client, after which the chain calls `_exit(0)`.

## 12. End-to-End Exploit Sequence

The complete solver follows this order:

1. Open short-lived TLS connections and parse each `101` session token.
2. Submit its CRC to command 8 and collect the returned linear equation.
3. Continue until the 128-bit matrix reaches full rank, then solve for the
   seal. A known seal may instead be supplied with `--seal`.
4. Open the final connection and create a checkpoint with command 1.
5. Use command 2, the seal-derived context codec, and offset `0x2370` to obtain
   PIE and scratch bases.
6. Upload the 0x1000-byte stage-one chain with command 5.
7. Commit the checkpoint and execute the computed five-command allocator
   route.
8. Use command 4 to overwrite the reclaimed record with encoded `rsp`, encoded
   `rip`, and a valid integrity hash.
9. Restore with command 6. Stage one leaks the GOT, derives libc, reads stage
   two, and pivots to it.
10. Stage two lists fd 9, asks the Python client to select the randomized flag
    filename, opens it with the exact allowed `openat2` tuple, and returns its
    contents.

## 13. Reproduction

The solver requires Python 3.10 or newer and no third-party packages. To
recover a fresh instance seal automatically:

```console
$ python3 solve.py HOST 1337 --workers 2
```

To skip the oracle phase with the seal from the captured instance:

```console
$ python3 solve.py HOST 1337 \
    --seal 4eaf20afbf05b2f1805d0261950df065
```

The recorded successful run ended with:

```text
[+] checkpoint alias route: [0, 0, 5, 0, 0] (snapshot list 1)
[+] PIE base:     0x55ff6e27d000
[+] scratch map:  0x203482812000
[+] write@libc:   0x7f1514c15690
[+] libc base:    0x7f1514af9000
[+] directory:    ['.', '..', 'flag_de56852d']
[+] opening:      flag_de56852d
zdk{4_ST4L3_CheckP0INt_s4nK_BeLOW_The_pOInTER_gUarD}
```

The offline verifier checks the captured seal, all four derived keys, pointer
decoding, allocator route, forged checkpoint values, and a synthetic full-rank
oracle reconstruction:

```console
$ python3 verify_offline.py
[+] seal and four derived keys verified
[+] PIE base recovered as 0x5604550a9000
[+] scratch mapping recovered as 0x21cd5e19d000
[+] allocator route verified: [0, 0, 5, 0, 0] -> list 1
[+] forged checkpoint encoding and hash verified
[+] reconstructed seal from 128 offline oracle rows
```

## Flag

```text
zdk{4_ST4L3_CheckP0INt_s4nK_BeLOW_The_pOInTER_gUarD}
```
