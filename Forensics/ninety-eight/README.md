# 99.8%

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | AncientDragon |
| Points | 162 |
| Solves at time of solving | 50 |
| Flag | `zdk{Q8IT_hI6H_g0a7ED}` |

> so my torrent stopped downloading randomly...idk why my claude couldn't help, could yours?

## Executive Summary

The handout is a captured qBittorrent session for an interrupted download of
`ubuntu_docs_backup_2025.iso` (stopped at "99.8%"). The evidence is deliberately
salted with **five plaintext decoy flags** — every one tagged `pH4K3_*` ("fake")
or `d3c0Y_*` ("decoy"). The blurb *"idk why my claude couldn't help"* is a taunt:
an assistant that just `grep`s for `zdk{` hands back a decoy.

The real flag is reconstructed from the scattered "qbcn" scheme described across
the logs:

```
key          = sha256( domain || piece_window || piece_length_word )
keystream[n] = sha256( key || uint32le(n) )      # 32-byte blocks, n = 0,1,2,…
keycheck     = sha256(key)[0:8]
```

Recovering the three key inputs from the evidence, the file's **final partial
piece** inside the `.!qB` partfile turns out to be an `HREG` container whose
stored `keycheck` matches the derived key. XOR-decrypting its body with the
keystream reveals an inner `QBCN` record holding the flag:

```
zdk{Q8IT_hI6H_g0a7ED}      ("qBit high, gOATED")
```

## Step 1 — Triage the evidence tree

```
evidence/
├── disk/         $MFT_fragment.bin, unallocated.bin
├── fragments/    download.tmp.!qB, cache_00.bin, cache_01.bin,
│                 thumb_2048.jpg, crc_report.txt, media_index.tmp
├── memory/       qbcore_2025_11_18.mem, carved_strings.txt
└── session/
    ├── BT_backup/  <infohash>.torrent, <infohash>.fastresume, queue
    ├── logs/       qbittorrent.log, disk_io.log, crash_report.txt
    └── qBittorrent-data.ini
```

`grep -r 'zdk{'` immediately turns up five flags — and every one of them is a
trap (full list in [`artifacts/evidence-map.md`](artifacts/evidence-map.md)):

| Token | Tell |
| --- | --- |
| `zdk{pH4K3_crc_fix}` | **pH4K3** = "fake" |
| `zdk{d3c0Y_malf_toc}` | **d3c0Y** = "decoy" |
| `zdk{d3c0Y_tracker_noise}` | **d3c0Y** = "decoy" |

So the flag is *not* lying around — it has to be rebuilt.

## Step 2 — Read the .torrent and .fastresume

Both are bencoded. The `.torrent` describes a single file:

```
name          = ubuntu_docs_backup_2025.iso
length        = 2098228
piece length  = 131072                 # 128 KiB  → 17 pieces (last is 1076 bytes)
pieces        = <declared 340, actually 339 bytes>   # last SHA-1 truncated by 1 (malf_toc)
```

The `.fastresume` says which piece stalled:

```
unfinished = [ { piece: 5, bitmask: ff ff 00 00, adler32: 1243252880 } ]
piece_priority = 01 07 01 07 01 01 07 …        # 07 = high priority
```

So piece **5** is the "missing 0.2%". The truncated `pieces` string and the
piece-5 pointer are both nudges toward key material — not the flag's hiding spot.

## Step 3 — Collect the qbcn scheme from the logs

Three log/temp files spell out the algorithm:

```
memory/carved_strings.txt : qbcn_kdf = sha256(domain || piece_window || piece_length_word)
fragments/media_index.tmp : qbcn_piece_window = pieces[0:16] ; piece_length_word = uint32le
session/logs/disk_io.log  : keycheck = sha256(key)[0:8]
                            stream_block[n] = sha256(key || uint32le(n))
```

That is a keystream cipher: derive a `key`, expand it into 32-byte blocks with a
`sha256(key‖counter)` construction, and XOR. `keycheck` gives us an oracle to
know when the key is right.

The three key inputs:

* **`piece_length_word`** — `uint32le(131072)` = `00 00 02 00`.
* **`piece_window`** — `pieces[0:16]`, i.e. the first 16 SHA-1 piece hashes
  (16 × 20 = 320 bytes) from the `.torrent`.
* **`domain`** — the one field not in the obvious files. It's in the memory dump.

## Step 4 — Pull the domain from the memory dump

`qbcore_2025_11_18.mem` is mostly high-entropy, but its tail carries a plain KDF
trace:

```
QKDF_TRACE_BEGIN
worker=qbcn-v1
domain_ascii=ninety-eight/qbcn/v1
domain_terminator=00
QKDF_TRACE_END
```

So `domain = b"ninety-eight/qbcn/v1\x00"` (note the explicit `00` terminator).

## Step 5 — Derive the key and confirm it with the keycheck

```python
import hashlib, struct
domain = b"ninety-eight/qbcn/v1\x00"
piece_window = pieces[0:320]                 # first 16 SHA-1 hashes
plw = struct.pack("<I", 131072)              # 00 00 02 00
key = hashlib.sha256(domain + piece_window + plw).digest()
# d2515578cf57736215ed384a7f75ee07e34fc38378be4fd454c9d52cffa40e68
keycheck = hashlib.sha256(key).digest()[:8]  # 32de14e7f9606b68
```

Now — where does that `keycheck` live? Dumping the file's **final partial piece**
from the `.!qB` partfile (offset `16 × 131072 = 2097152`) shows a small header:

```
4852 4547 0200 3d00 32de 14e7 f960 6b68 …
H R E G  ver  len  <keycheck 32de14e7f9606b68>
```

`32de14e7f9606b68` **exactly matches** the derived `keycheck` — the key is right,
and the flag lives in this `HREG` container, not in piece 5.

## Step 6 — Decrypt the HREG → QBCN container

The outer container is `magic "HREG" | ver=2 (u16le) | clen=61 (u16le) |
keycheck(8) | ciphertext(61)`. XOR the ciphertext with the keystream
(`sha256(key‖uint32le(n))`, `n` from 0):

```python
def keystream(key, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", i)).digest(); i += 1
    return out[:n]

ct    = blob[16:16+61]
inner = bytes(a ^ b for a, b in zip(ct, keystream(key, 61)))
# b'QBCN\x01\x00\x15\x00zdk{Q8IT_hI6H_g0a7ED}...'
```

The plaintext is a second container: `magic "QBCN" | ver=1 | flaglen=0x15=21 |
flag`. The `QBCN` magic and the `flaglen == 21` that exactly matches the flag
length are an unambiguous "correct decrypt" signal.

```
zdk{Q8IT_hI6H_g0a7ED}
```

## Flag

```
zdk{Q8IT_hI6H_g0a7ED}
```

Leetspeak for **"qBit high, gOATED"** — `Q8IT` = QBIT, `hI6H` = HIGH,
`g0a7ED` = GOATED.

## Reproduce

```bash
unzip forensics_ninety_eight.zip        # -> evidence/
python3 solve.py evidence
```

`solve.py` parses the `.torrent`, derives the key, asserts the `keycheck` against
the `HREG` header, decrypts the `QBCN` record, and prints the flag — no
hard-coded offsets beyond the documented container layout.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end solver: torrent → key → keycheck verify → HREG/QBCN decrypt → flag |
| [`artifacts/decryption-trace.txt`](artifacts/decryption-trace.txt) | Full key derivation, HREG header, and the decrypted QBCN bytes |
| [`artifacts/evidence-map.md`](artifacts/evidence-map.md) | What each evidence file contributes, and every decoy with its tell |
| [`challenge/forensics_ninety_eight.zip`](challenge/forensics_ninety_eight.zip) | Original handout |

## Why it's tricky

Nothing here is one lookup: the flag is split into *inputs* (`domain` in the
memory dump, `piece_window` in the torrent, `piece_length_word` and the two
sha256 constructions across three log files), the plaintext flags are all decoys,
and the loudest pointers (`crc mismatched chunks`, the piece-5 `unfinished`
marker, the truncated `pieces` blob) steer you away from the actual container in
the file's final piece. The `keycheck` and the `QBCN` magic are what let you
*prove* you've reconstructed the right one.
