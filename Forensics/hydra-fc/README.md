# Hydra FC

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | TitanCode |
| Points | 122 |
| Solves at time of solving | 127 |
| Flag | `zdk{Mess1_0R_RONa1d0}` |

> Hydra FC scored at 90+13 after the Floating Stadium tracking network
> desynchronized. The replay does not match the pitch. Recover what the analytics
> gateway accepted beneath the waves.

## Executive Summary

`hydra_uplink.pcapng` captures four ball-tracking cameras
(**CAM-NORTH / SOUTH / EAST / WEST**) streaming **msgpack** telemetry over
**WebSocket** to an analytics gateway (`10.13.0.2:8080`) — the traffic "beneath
the waves." A source map served at `/assets/replay.js.map` leaks the entire
protocol, including the gateway's fatal shortcut:

```js
// Gateway v3.1: sequence is uint16. FIXME: make rollover-aware.
export function shouldReplace(current, incoming) {
  return current === undefined || incoming.seq > current.seq;   // naive
}
```

Each 40 ms "match bucket" keeps the frame with the highest 16-bit `seq`. Three
cameras carry the genuine match (the ball drifting around midfield). **CAM-EAST**
abuses the non-rollover-aware comparison to smuggle a covert payload: it injects
extra frames whose `seq` sits near the uint16 ceiling (so they win their buckets)
and whose `BALL` is parked on an exact grid cell with `confidence == 1.0`. Plot
those injected ball positions on the code's own 25×25 grid and a **QR code**
appears — 326 modules, drawn **mirrored**. Decoding it yields the flag:

```
zdk{Mess1_0R_RONa1d0}
```

The "replay does not match the pitch" because the accepted stream is a QR code,
not football; "recover what the gateway accepted" is the injected CAM-EAST layer.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end solver: pcap → msgpack → isolate CAM-EAST injection → paint QR → decode |
| [`msgpack_dec.py`](msgpack_dec.py) | Dependency-free pure-python msgpack decoder |
| [`artifacts/replay.js.map`](artifacts/replay.js.map) | The leaked source map (protocol disclosure) |
| [`artifacts/telemetry.js`](artifacts/telemetry.js) | Readable client source extracted from the map |
| [`artifacts/frames-summary.txt`](artifacts/frames-summary.txt) | Per-stream seq/offset stats + the injection, side by side |
| [`artifacts/qr.png`](artifacts/qr.png) | The reconstructed, de-mirrored QR |
| [`artifacts/qr.txt`](artifacts/qr.txt) | ASCII render of the QR |
| [`challenge/forensics_hydra_fc.zip`](challenge/) | Original handout (`hydra_uplink.pcapng`) |

Reproduction needs `tshark` (to read the pcap) and `zbarimg` (final QR decode);
everything else is the Python standard library.

## 1. Triage — What's in the Capture

```console
$ capinfos hydra_uplink.pcapng      # 8285 packets, 1.54 s
$ tshark -r hydra_uplink.pcapng -q -z io,phs
    http        frames:10
      json      frames:1
    websocket   frames:3942
```

Ten HTTP frames set the scene; the payload is 3942 WebSocket frames. The HTTP
shows four WebSocket upgrades — `GET /live?stream=CAM-{NORTH,SOUTH,EAST,WEST}` —
from `10.13.0.11-14` to the gateway, plus one asset fetch:
`GET /assets/replay.js.map` → `200 application/json`.

## 2. The Leaked Protocol

The source map is a gift. Its `sourcesContent` is the client
[`telemetry.js`](artifacts/telemetry.js):

```js
import { decode } from "@msgpack/msgpack";
const offsets = new Map();
export function observeSync(message) {
  offsets.set(message.stream, message.match_us - message.mono_us);
}
export function matchBucket(message) {
  return Math.floor((message.mono_us + offsets.get(message.stream)) / 40000);
}
export function shouldReplace(current, incoming) {           // uint16, NOT rollover-aware
  return current === undefined || incoming.seq > current.seq;
}
export function debugGrid(ball) {
  return [ Math.round(((ball.x + 52.5) / 105) * 24),
           Math.round(((34 - ball.y) / 68) * 24) ];
}
```

So each WebSocket message is msgpack, and the gateway:

1. reads a per-stream **sync offset** `= match_us − mono_us` from `SYNC` messages;
2. assigns every `FRAME` to a **40 ms bucket** on the shared match timeline;
3. per bucket, keeps the frame with the **highest `seq`** (a 16-bit counter,
   compared naïvely);
4. maps the tracked **`BALL`** to a **25-module grid** (`0…24`) via `debugGrid`.

## 3. Decoding the Streams

msgpack is trivial to parse; [`msgpack_dec.py`](msgpack_dec.py) is a small
pure-python decoder. Unmasking every WebSocket payload with `tshark` and decoding
gives two message types: 16 `SYNC` and 3926 `FRAME`. Each `FRAME` carries
`stream, seq, mono_us`, and 23 tracked objects (`H01–H11`, `S01–S11`, `BALL`)
with `x, y, confidence`.

Applying the sync offsets aligns all four cameras onto the **same 900 buckets**.
The per-stream statistics (full table in
[`artifacts/frames-summary.txt`](artifacts/frames-summary.txt)) immediately flag
the odd one out:

```
CAM-NORTH  frames= 900  seq[min=12000 max=12899]   conf==1.0 frames=0
CAM-SOUTH  frames= 900  seq[min=28000 max=28899]   conf==1.0 frames=0
CAM-EAST   frames=1226  seq[min=    0 max=65535]   conf==1.0 frames=326   <-- anomaly
CAM-WEST   frames= 900  seq[min=43000 max=43899]   conf==1.0 frames=0
```

Three cameras use small, tidy `seq` bands. **CAM-EAST has 326 extra frames and a
`seq` that spans the entire uint16 range** — the signature of a deliberate
rollover abuse.

## 4. Isolating the Injection

Rendering each stream's ball positions on the grid settles it: NORTH, SOUTH and
WEST all trace the **same real ball** loitering in midfield, while **CAM-EAST
alone draws a QR-shaped figure**. Zooming into the buckets where CAM-EAST sent
*two* frames shows exactly how the smuggling works:

```
bucket=154502 seq=    0 conf=0.970 ball=(-3.03,-10.84) grid=(11,16)  <- real ball
bucket=154502 seq=65400 conf=1.000 ball=(-52.50, 34.00) grid=( 0, 0) <- injected QR module
bucket=154503 seq=    1 conf=0.976 ball=(-2.93,-11.11) grid=(11,16)  <- real ball
bucket=154503 seq=65401 conf=1.000 ball=(-48.12, 34.00) grid=( 1, 0) <- injected QR module
```

Every injected frame is unmistakable:

- **`confidence == 1.0`** exactly (real tracking is always `< 1.0`),
- **`seq` near the uint16 ceiling** (`65400+`) so the naïve gateway prefers it,
- **`BALL` parked on an exact grid-cell centre** (e.g. `x=-52.5, y=34` → module
  `(0,0)`), i.e. one QR module per frame.

That gives a clean, exact selector: **the QR is the set of CAM-EAST frames with
`confidence == 1.0`.** No thresholds, no rounding noise.

> Note on the naïve accept path: taking the gateway's literal max-`seq` winner
> per shared bucket accepts CAM-EAST in 628 buckets and a real camera in 272
> (because CAM-EAST's wrapped-around low `seq` values *lose* those). That mixed
> result is a QR polluted by the real ball cluster — it will not scan. The
> `confidence == 1.0` filter recovers what CAM-EAST actually *tried* to inject.

## 5. Reconstructing and Decoding the QR

Painting the 326 injected modules produces a **25×25 grid = QR version 2**, with
the three finder patterns, timing rows and an alignment pattern all intact. A raw
scan still fails — because the code is drawn **mirrored** (the `x` axis is
flipped relative to a normal QR). Emitting the bitmap and trying all eight
orientations, `zbarimg` locks on immediately:

```console
$ python3 solve.py
[*] EAST injected (confidence==1.0) frames: 326
[*] QR black modules: 326
...
[+] FLAG: zdk{Mess1_0R_RONa1d0}
```

The de-mirrored code is committed as [`artifacts/qr.png`](artifacts/qr.png) /
[`artifacts/qr.txt`](artifacts/qr.txt).

```
zdk{Mess1_0R_RONa1d0}
```

A fitting football pun — **Messi or Ronaldo** — and the "90+13" scoreline was
pure flavour for the stoppage-time desync.

## 6. Reproducing

```console
$ python3 solve.py                       # extracts the pcap from challenge/ and solves
$ python3 solve.py path/to/hydra_uplink.pcapng
```

## Root Cause and Fix

- **Root cause:** the gateway deduplicates frames by a **16-bit sequence number
  compared as a plain integer** (`incoming.seq > current.seq`). A sender that
  wraps `seq` past 65535 — or simply parks it near the ceiling — can override
  legitimate frames in the same time bucket, injecting arbitrary "accepted"
  telemetry. The client even documents the bug: `FIXME: make rollover-aware`.
- **Fix:** compare sequence numbers with **serial-number arithmetic** (RFC 1982),
  i.e. treat `a` as newer than `b` iff `0 < (a − b) mod 2¹⁶ < 2¹⁵`, or use a
  wide/monotonic counter. Authenticate stream sources so one camera cannot post
  frames attributed to the shared match state, and treat `confidence == 1.0` as
  the implausible sentinel it is.

## Lessons

- **Read the source map.** Shipping `.map` files hands an attacker (and a
  solver) the exact protocol, field names, and — here — the vulnerable function.
- **Anomalies live in the metadata.** Frame counts, `seq` ranges, and a
  suspiciously perfect `confidence` isolated the malicious stream before any
  pixel was plotted.
- **Know your rendering gotchas.** A structurally perfect QR that refuses to scan
  is usually **mirrored or rotated** — brute-force the eight orientations before
  suspecting the data.
