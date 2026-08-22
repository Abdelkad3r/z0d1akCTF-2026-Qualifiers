# Dead Current

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | pokymono |
| Points | 148 |
| Solves at time of solving | 63 |
| Flag | `zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}` |

> A Pelagos oceanographic beacon went silent during a live migration from an
> offshore research vessel to shore.

## Executive Summary

The evidence is a **CRIU 4.x checkpoint** of a Go relay process
(`/opt/pelagos/relay`) plus the stripped ELF that owned it. During the live
migration the process still held **one sealed incident record that never reached
storage**, and the per‑incident key was "deleted." Both survive in the
checkpoint.

The solve has three parts:

1. **Reverse the relay's crypto** from the stripped Go binary. Go keeps its own
   symbol table in `.gopclntab`, so the `main.*` functions are recoverable even
   though the ELF is stripped. Running the binary under gdb and jumping into its
   `selfTest` reveals the exact scheme:
   - `incidentKey = SHA256(state32 ‖ streamID[16] ‖ ctx8[8])` (`main.deriveIncidentKey`)
   - `keystream[i] = SHA256(incidentKey ‖ uint32le(i))`, `pt = ct ⊕ keystream` (`main.xorStream`)
2. **Carve the deleted ghost file** — the spool file
   `/tmp/.relay-case-LM-a3febe5e3ae7`, whose content is an **`IRF1`** record
   giving the `streamID`, a `nonce`, and the ciphertext.
3. **Recover the RelayState master secret** from the captured process memory
   (`pages-2.img`): the state serializes an incident record as
   `{u32 type=4, u32 len}` followed by the 32‑byte master secret; in the live
   state the incident was already spooled, so the record is empty (`{4,0}`) and
   the secret sits immediately after the marker.

Deriving the key and running the stream cipher decrypts the record to
`INC15\0` + the flag:

```
zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}
```

The flag names the lesson: a checkpoint is an **afterimage** — the "deleted"
incident key and record outlive their erasure inside the migration image.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | Self‑contained solver: unpack checkpoint → carve ghost → recover master secret → derive key → decrypt |
| [`artifacts/relay-crypto.md`](artifacts/relay-crypto.md) | Recovered `main.*` functions, gdb ground‑truth of the KDF + cipher |
| [`artifacts/pcln.py`](artifacts/pcln.py) | `.gopclntab` parser used to recover Go symbols from the stripped ELF |
| [`artifacts/criimg.py`](artifacts/criimg.py) | Minimal CRIU length‑prefixed‑protobuf image parser |
| [`artifacts/incident-IRF1.bin`](artifacts/incident-IRF1.bin) | The carved `IRF1` sealed incident record (from the ghost file) |
| [`artifacts/incident-plaintext.bin`](artifacts/incident-plaintext.bin) | The decrypted incident record |
| [`artifacts/decryption-params.txt`](artifacts/decryption-params.txt) | All recovered parameters (secret, streamID, nonce, key) |
| [`challenge/forensics_dead-current.zip`](challenge/) | Original handout (docs + `relay` ELF + `checkpoint.tar`) |

Reproduction is pure Python standard library. `relay` analysis used gdb inside a
`linux/amd64` container (the ELF is Linux x86‑64).

## 1. Triage — a CRIU checkpoint

`checkpoint.tar` unpacks to CRIU image files (length‑prefixed protobuf, common
magic `0x54564319`):

```
pstree.img  mm-8.img  pagemap-8.img  pages-1.img  pages-2.img
files.img   fdinfo-2.img  sk-queues.img  ghost-file-1.img  remap-fpath.img ...
```

The handout spells out the two footholds:

> The queued socket packet is a compact `QMSG` structure whose pointer can be
> translated through the captured pagemap; the deleted ghost file begins with an
> `IRF1` record.

So: a queued socket packet (`sk-queues.img`) and a deleted file recovered as a
CRIU **ghost** (`ghost-file-1.img`).

## 2. Reversing the relay's crypto

`relay` is a **Go 1.26.5** static ELF, stripped of its symbol table — so
`go tool objdump` reports *"no symbol section."* But Go embeds its own metadata
in `.gopclntab`; [`artifacts/pcln.py`](artifacts/pcln.py) parses that header
(magic `0xFFFFFFF1`) and recovers every function name and address:

```
main.deriveIncidentKey  0x4a3d40
main.xorStream          0x4a3e40
main.marshalQueue       0x4a3c60
main.queueDigest        0x4a2f80
main.selfTest           0x4a3fa0
crypto/sha256.Sum256    0x490a40      <- the only primitive
```

Static reading shows `deriveIncidentKey` builds a **56‑byte** buffer and calls
`Sum256`, and `xorStream` XORs 32‑byte blocks produced by `Sum256`. The exact
inputs aren't obvious from the disassembly, and `main.selfTest` — which wires the
routines together — is never reached at runtime (an `init()` prints
*"pelagos relay: no live transport after checkpoint capture"* and exits).

**So I ran it in gdb** (linux/amd64 container), broke at `main.main`, and
`jump`ed into `selfTest`, breaking on the `Sum256` calls. That yields ground
truth (full trace in [`artifacts/relay-crypto.md`](artifacts/relay-crypto.md)):

```
deriveIncidentKey:  SHA256( state32[32] || streamID[16] || ctx8[8] ) = incidentKey
  (test) state32  = SHA256("deleted incident key")
  (test) streamID = "PELAGOS\0..."
  (test) ctx8     = "SOGALEP\0"
xorStream:          keystream[i] = SHA256( incidentKey || uint32le(i) )
                    ciphertext   = plaintext XOR keystream
```

Verified against the captured cipher output: `ct[0:8] = pt[0:8] ⊕
SHA256(incidentKey‖0)[0:8]` matches byte‑for‑byte.

## 3. Carving the sealed incident record

`ghost-file-1.img` is a CRIU ghost file: `common+ghost magic (8) | u32 size |
GhostFileEntry | raw content`. `files.img` names the deleted path,
`/tmp/.relay-case-LM-a3febe5e3ae7`, and the raw content is an **`IRF1`** record
(207 bytes) whose fields fall out exactly by length:

```
"IRF1"(4) | ver/hdr(4) | streamID(16) | nonce(12) | len=167(u32) | ciphertext(167)
```

- `streamID = 1dcd1906f764dba6b7a054970cd95e17` — the same 16 bytes carried as the
  token in the queued `QMSG` packet (`sk-queues.img`), confirming it is the KDF's
  `streamID`.
- `nonce = 42ca22ec2ed69c97bde0bbe8`; its first 8 bytes are the KDF `ctx8`.
- `ciphertext = irf[40:207]` (167 bytes — note this equals the serialized
  `RelayState` size).

## 4. Recovering the master secret from memory

`state32` is the relay's persistent master secret — a field of the `RelayState`,
present in the captured heap (`pages-2.img`). From `selfTest`'s serialization the
state lays out an incident record as `{u32 type=4, u32 len}` immediately followed
by the 32‑byte master secret. In the **live** state the incident had already been
written to the spool, so the record is **empty** — `{4,0}` — and the secret
follows the 8‑byte marker `04 00 00 00 00 00 00 00`:

```
pages-2 @ 0xb8058:  04 00 00 00 00 00 00 00              <- {type=4, len=0}
pages-2 @ 0xb8060:  07393d2c6c9054f4de142a3a8de74558
                    887c7211d6166370b0b48b8134f02247    <- state32 (master secret)
```

(The `QMSG` pointer, translated through `pagemap-8.img`, lands on an *older*
snapshot of the same state that still embeds a `{4,207}` incident — a decoy; the
live secret is the one after the empty `{4,0}` record.)

## 5. Deriving the key and decrypting

```python
incidentKey = SHA256(state32 || streamID || nonce[0:8])
            = a87d7b580db1bdb5e9a5e765da491e89682776d5bd4568df997891b69486f9fd
plaintext   = ciphertext XOR ⨁ SHA256(incidentKey || uint32le(i))
            = b"INC15\x00zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}..."
```

```
zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}
```

## 6. Reproducing

```console
$ python3 solve.py
[*] streamID = 1dcd1906f764dba6b7a054970cd95e17
[*] nonce    = 42ca22ec2ed69c97bde0bbe8   (ctx8 = first 8 bytes)
[*] ciphertext = 167 bytes
[*] master secret @ pages-2 0xb8060: 07393d2c...34f02247
[*] incident record: b'INC15\x00zdk{CRIU_4fT3RIMAGE_..._oCqDD59c4}'
[+] FLAG: zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}
```

## Root Cause and Lessons

- **A checkpoint is an afterimage.** CRIU captures *everything* — deleted files
  become ghost images, freed/queued buffers persist, and secrets a process
  "zeroised" a moment later are still frozen in `pages-*.img`. Treat migration
  images as sensitive as the live process memory.
- **"Stripped" Go isn't opaque.** `.gopclntab` survives ELF stripping; parse it
  to recover function names and drive a targeted dynamic analysis.
- **Let the program tell you the algorithm.** Rather than fight the
  disassembly, jumping into the binary's own `selfTest` under gdb produced exact,
  labelled test vectors for the KDF and cipher.
- **Deriving keys from data you control is the crack.** `streamID` and `nonce`
  live in the record itself; only the persistent `state32` had to be lifted from
  memory — and it was sitting right after an empty incident marker.
