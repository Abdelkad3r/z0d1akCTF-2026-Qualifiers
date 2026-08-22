# Black Box

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | Praneet |
| Points | 118 |
| Solves at time of solving | 153 |
| Flag | `zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}` |

> A survey drone crashed during a test flight. Forensics recovered the flight
> recorder, but the telemetry module relies on an unclassified architecture.
> Standard analytical utilities report raw binary garbage and recorder suffered
> during impace.

## Executive Summary

`blackbox.bin` is a flight-recorder image consisting of 245 fixed-size 16-byte
records, each introduced by the ASCII magic `BX`. Every multi-byte field in the
container is stored **big-endian** — that is the "unclassified architecture" the
brief alludes to, and the reason little-endian-assuming tooling renders the file
as noise.

Three record types are present. Two of them (120 GPS records and 120 telemetry
records) carry a plausible but entirely synthetic flight profile and are
complete and internally consistent — they are flavour, not payload. The
remaining five records carry the flag, split into 8-byte fragments.

The "impact damage" is a **physical reordering**: the five flag fragments are
scattered through the image in the order 3, 0, 1, 4, 2. Each record carries its
own logical sequence number, so the damage is fully recoverable by sorting.

The fragment payloads are obfuscated with a repeating two-byte XOR key. The key
is not hidden — it is sitting in plain sight in the fragment records' trailer
field, which is the constant `0xDEAD` where the other record types store a
sequence-derived checksum. Sorting the fragments, concatenating them and XOR-ing
with `DE AD` yields the flag, and the record's zero padding decodes to clean
`0x00` bytes, which independently confirms the key.

The supplied [solver](solve.py) performs the whole process end to end and
validates every structural assumption before printing the flag.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/black-box.zip`](challenge/black-box.zip) | Original handout | `db7803197eba9a81c36ee655780f6039f3dcaec2612454ce35da4955535f7efd` |
| [`challenge/blackbox.bin`](challenge/blackbox.bin) | Extracted recorder image, 3,920 bytes | `03e669ce685689b6c7510f3de6d3466c9432b464c387e6aab9db25563f2fa015` |
| [`solve.py`](solve.py) | Standalone solver, no third-party dependencies | — |
| [`artifacts/records.csv`](artifacts/records.csv) | All 245 records, parsed and decoded | — |
| [`artifacts/record-map.txt`](artifacts/record-map.txt) | Annotated hexdump of representative records | — |

## 1. Initial Triage

The handout contains a single file with no extension hints and no recognised
signature:

```console
$ unzip -l black-box.zip
  Length      Name
---------     ----
     3920     blackbox.bin

$ file blackbox.bin
blackbox.bin: data

$ strings -n 6 blackbox.bin
$
```

`strings` returning nothing is the first useful signal: the file is not text and
is not a compressed or encrypted archive either — a compressed blob would not be
this structurally regular. The size is the second signal:

```
3920 = 16 x 245
```

A whole number of small fixed-size records is the classic shape of a flight
recorder or logging ring buffer.

## 2. Recognising the Record Structure

A hexdump immediately confirms the 16-byte period, with an obvious `BX` magic at
every boundary:

```console
$ xxd blackbox.bin | head -8
00000000: 4258 0100 0000 414f 8bac 429e 511a 0000  BX....AO..B.Q...
00000010: 4258 0200 0000 0064 00c8 03d4 0000 0000  BX.....d........
00000020: 4258 0100 0001 414f 8c15 429e 5127 1337  BX....AO..B.Q'.7
00000030: 4258 0200 0001 0065 00c7 03d4 0001 4242  BX.....e......BB
00000040: 4258 0100 0002 414f 8c7e 429e 5134 266e  BX....AO.~B.Q4&n
00000050: 4258 0200 0002 0066 00c6 03d4 0002 8484  BX.....f........
00000060: 4258 0100 0003 414f 8ce7 429e 5141 39a5  BX....AO..B.QA9.
00000070: 4258 0200 0003 0067 00c5 03d4 0003 c6c6  BX.....g........
```

Reading down the columns rather than across the rows makes the field boundaries
fall out:

| Offset | Size | Field | Evidence |
| --- | --- | --- | --- |
| 0 | 2 | magic `BX` | constant at every 16-byte boundary |
| 2 | 1 | record type | takes only the values 1, 2, 3 |
| 3 | 1 | flags | always `0x00` |
| 4 | 2 | sequence number | counts `0000, 0001, 0002, …` — **big-endian** |
| 6 | 8 | payload | type-dependent |
| 14 | 2 | trailer | type-dependent, see below |

The sequence number is the decisive endianness tell. Read big-endian it counts
`0, 1, 2, 3, …`; read little-endian it would jump `0, 256, 512, 768, …`. Every
other multi-byte field in the file follows the same convention.

This is what the brief means by an "unclassified architecture": there is no
exotic instruction set involved, just network byte order on a little-endian
analyst workstation.

## 3. Decoding the Two Telemetry Record Types

### Type 1 — GPS

The payload is two big-endian IEEE-754 single-precision floats:

```console
$ python3 -c "import struct; print(struct.unpack('>ff', bytes.fromhex('414f8bac429e511a')))"
(12.971599578857422, 79.15840148925781)
```

12.9716 °N, 79.1584 °E. The 120 GPS records trace a perfectly straight line from
(12.97160, 79.15840) to (12.98350, 79.17030) — roughly Vellore, Tamil Nadu.

The track is linear to the last decimal place, which is worth noting: it is
generated data, not a recording, so there is no point looking for an anomaly in
it.

### Type 2 — Telemetry

The payload is four big-endian `uint16` values:

```console
$ python3 -c "import struct; print(struct.unpack('>HHHH', bytes.fromhex('0064 00c8 03d4 0000'.replace(' ',''))))"
(100, 200, 980, 0)
```

Across the 120 records these behave as altitude (100 → 219, monotonically
rising), battery (200 → 81, monotonically falling), a constant barometric
reference of 980, and a tick counter. Again: synthetic, monotonic, and free of
any embedded anomaly.

### The Trailer Field

The trailer looked like a checksum, and it is — a trivially structured one. Its
value is an exact multiple of the sequence number, with a different multiplier
per record type:

```
type 1:  0x0000, 0x1337, 0x266e, 0x39a5, 0x4cdc, …   step 0x1337
type 2:  0x0000, 0x4242, 0x8484, 0xc6c6, 0x0908, …   step 0x4242
```

so `trailer == (seq * multiplier) & 0xFFFF`. The solver verifies this for all
240 telemetry records; **every one passes**, which is how we establish that the
telemetry half of the image is undamaged and that the corruption referenced in
the brief lies elsewhere.

## 4. Locating the Payload

Filtering by record type gives the answer immediately:

```console
$ python3 solve.py
blackbox.bin: 245 records
  type 1: 120 records, seq 0..119, 0 bad trailers
  type 2: 120 records, seq 0..119, 0 bad trailers
  type 3:   5 records, seq 0..4, 0 bad trailers
```

Five records of a third type, sitting among 240 records of filler. Their layout
is identical, but two things distinguish them:

```
0x0080  BX 03 00 0003  ac 98 92 c3 99 f2 93 ec  dead
0x00b0  BX 03 00 0000  a4 c9 b5 d6 9b c1 9b c0  dead
0x00e0  BX 03 00 0001  bb e3 e9 99 ac d4 81 cf  dead
0x01f0  BX 03 00 0004  8d 9a ed df a3 ad de ad  dead
0x0240  BX 03 00 0002  92 c3 9f df 87 f2 ae cc  dead
```

1. **Their sequence numbers do not match their file order.** They appear at
   offsets `0x80, 0xb0, 0xe0, 0x1f0, 0x240` carrying sequence numbers
   3, 0, 1, 4, 2. This is the "recorder suffered during impact" — the records
   survived intact but were written out of order. Because each record is
   self-describing, the damage is losslessly repairable.

2. **Their trailer is the constant `0xDEAD`**, not a sequence-derived checksum.
   A field that is per-record data for every other type, but a fixed value here,
   is the challenge handing over the key.

## 5. Recovering the Flag

Sort by sequence number, concatenate the five 8-byte payloads into a 40-byte
blob, and XOR with the repeating key `DE AD`:

```python
fragments = sorted((r for r in records if r.type == 3), key=lambda r: r.seq)
blob      = b"".join(r.payload for r in fragments)
plaintext = bytes(b ^ b"\xde\xad"[i % 2] for i, b in enumerate(blob))
```

```
ciphertext : a4 c9 b5 d6 9b c1 9b c0 bb e3 e9 99 ac d4 81 cf 92 c3 9f df 87 f2 ae cc
             ac 98 92 c3 99 f2 93 ec 8d 9a ed df a3 ad de ad
key        : de ad de ad de ad de ad de ad de ad de ad de ad de ad de ad de ad de ad
             de ad de ad de ad de ad de ad de ad de ad de ad
plaintext  : b'zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}\x00\x00\x00'
```

The 37-character flag occupies the payload exactly, and the final record's three
bytes of zero padding decode to `0x00 0x00 0x00`. That is a free correctness
check: an incorrect key would produce three arbitrary bytes there, so the clean
padding confirms both the key and the fragment ordering.

```
zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}
```

### A note on the flag text

The plaintext reads `bLnArY` and `par5LnG`, with a capital **L** where "binary"
and "parsing" call for an **I**. This is the literal decode, not a transcription
error — the bytes are `0x4C`, and `0x49` would require a different key at
exactly those two positions while leaving all 38 other bytes untouched. The
challenge author's leetspeak generator evidently substitutes `i → l` before
randomising case. The same generator's fingerprint is visible in the
[stars-below](../../Reverse/stars-below/README.md) flag, where `loader` becomes
`1OAd3r` (`l → 1`).

Submit the flag exactly as decoded.

## 6. Reproducing

```console
$ cd Forensics/black-box
$ python3 solve.py
blackbox.bin: 245 records
  type 1: 120 records, seq 0..119, 0 bad trailers
  type 2: 120 records, seq 0..119, 0 bad trailers
  type 3:   5 records, seq 0..4, 0 bad trailers

  flag fragments (physical order -> logical order):
    0x0080  seq 3  ac 98 92 c3 99 f2 93 ec
    0x00b0  seq 0  a4 c9 b5 d6 9b c1 9b c0
    0x00e0  seq 1  bb e3 e9 99 ac d4 81 cf
    0x01f0  seq 4  8d 9a ed df a3 ad de ad
    0x0240  seq 2  92 c3 9f df 87 f2 ae cc

Flag: zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}
Wrote artifacts/records.csv
```

The solver requires only the Python 3 standard library.

## Lessons

- **Size factorisation is triage.** `3920 = 16 × 245` pointed at a fixed-size
  record container before a single byte was interpreted.
- **Verify the whole container before hunting for the payload.** Confirming that
  all 240 telemetry trailers checksum correctly ruled out three quarters of the
  file in one step and localised the "damage" to five records.
- **A field that is variable everywhere except in one record type is a message.**
  The `0xDEAD` trailer was the key, delivered in the same slot that holds a
  checksum elsewhere.
- **Look for a self-check in the plaintext.** The zero padding at the end of the
  final fragment turned "this decode looks plausible" into "this decode is
  correct".
