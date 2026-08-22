#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - Hydra FC (Forensics, 122 pts)

`hydra_uplink.pcapng` is four camera streams (CAM-NORTH/SOUTH/EAST/WEST)
WebSocket-uploading msgpack telemetry to an analytics gateway. A leaked source
map (/assets/replay.js.map) documents the protocol:

  * per-stream sync offset  = match_us - mono_us            (from SYNC messages)
  * matchBucket             = floor((mono_us + offset)/40000)   -> 40 ms buckets
  * shouldReplace keeps the higher uint16 `seq` per bucket  ("FIXME: rollover")
  * debugGrid maps the BALL (x, y) onto a 24-module grid

CAM-EAST exploits the non-rollover-aware gateway to smuggle a 25x25 QR code:
its injected frames carry confidence == 1.0 and near-max seq, one QR module each.
Filtering EAST frames to confidence == 1.0 paints the QR exactly; it is drawn
mirrored (so a raw scan fails) - we try all orientations.

Dependencies: tshark (to read the pcap) and zbarimg (final QR decode).

    python3 solve.py [hydra_uplink.pcapng]      # extracts from challenge/ zip if omitted
"""
import sys, os, io, re, zlib, struct, subprocess, zipfile, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import msgpack_dec

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {"10.13.0.11": "CAM-NORTH", "10.13.0.12": "CAM-SOUTH",
       "10.13.0.13": "CAM-EAST",  "10.13.0.14": "CAM-WEST"}


def find_pcap(argv):
    if len(argv) > 1:
        return argv[1]
    z = os.path.join(HERE, "challenge", "forensics_hydra_fc.zip")
    tmp = tempfile.mkdtemp()
    with zipfile.ZipFile(z) as zf:
        name = [n for n in zf.namelist() if n.endswith(".pcapng")][0]
        zf.extract(name, tmp)
        return os.path.join(tmp, name)


def extract_ws(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "websocket",
         "-T", "fields", "-e", "ip.src", "-e", "websocket.payload"],
        capture_output=True, text=True, check=True).stdout
    msgs = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        src, hexp = line.split("\t", 1)
        if not hexp:
            continue
        m = msgpack_dec.loads(bytes.fromhex(hexp))
        m["_src"] = SRC.get(src, src)
        msgs.append(m)
    return msgs


def ball(m):
    return next(o for o in m["objects"] if o["id"] == "BALL")


def debug_grid(b):                       # from the leaked telemetry.js
    return (round(((b["x"] + 52.5) / 105) * 24),        # col
            round(((34 - b["y"]) / 68) * 24))           # row


def write_png(mat, path, scale=16, quiet=8):
    n = len(mat)
    size = (n + 2 * quiet) * scale
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            mx, my = x // scale - quiet, y // scale - quiet
            black = 0 <= mx < n and 0 <= my < n and mat[my][mx]
            raw.append(0 if black else 255)
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
           + chunk(b"IEND", b""))
    open(path, "wb").write(png)


def orientations(m):
    n = len(m)
    yield m
    yield [[m[n-1-c][r] for c in range(n)] for r in range(n)]        # rot90
    yield [[m[n-1-r][n-1-c] for c in range(n)] for r in range(n)]    # rot180
    yield [[m[c][n-1-r] for c in range(n)] for r in range(n)]        # rot270
    mm = [row[::-1] for row in m]                                    # mirror + rots
    yield mm
    yield [[mm[n-1-c][r] for c in range(n)] for r in range(n)]
    yield [[mm[n-1-r][n-1-c] for c in range(n)] for r in range(n)]
    yield [[mm[c][n-1-r] for c in range(n)] for r in range(n)]


def main():
    pcap = find_pcap(sys.argv)
    print(f"[*] reading {pcap}")
    msgs = extract_ws(pcap)
    frames = [m for m in msgs if m.get("type") == "FRAME"]
    print(f"[*] {len(msgs)} WS messages, {len(frames)} FRAMEs, "
          f"{sum(1 for m in msgs if m.get('type')=='SYNC')} SYNCs")

    # per-stream sync offset from SYNC messages
    offset = {m["stream"]: m["match_us"] - m["mono_us"]
              for m in msgs if m.get("type") == "SYNC"}
    print(f"[*] offsets: {offset}")

    # CAM-EAST injects the QR: frames with confidence == 1.0, one module each
    qr_frames = [m for m in frames
                 if m["stream"] == "CAM-EAST"
                 and abs(ball(m)["confidence"] - 1.0) < 1e-12]
    print(f"[*] EAST injected (confidence==1.0) frames: {len(qr_frames)}")

    mat = [[False] * 25 for _ in range(25)]
    for m in qr_frames:
        c, r = debug_grid(ball(m))
        if 0 <= r < 25 and 0 <= c < 25:
            mat[r][c] = True
    print(f"[*] QR black modules: {sum(sum(r) for r in mat)}")
    print("\n".join("".join("#" if v else " " for v in row) for row in mat))

    # render + decode (QR is mirrored -> try all orientations)
    for i, om in enumerate(orientations(mat)):
        p = os.path.join(HERE, f"_qr_{i}.png")
        write_png(om, p)
        r = subprocess.run(["zbarimg", "--quiet", "--raw", p],
                           capture_output=True, text=True)
        os.remove(p)
        flag = r.stdout.strip()
        if flag:
            print(f"\n[+] FLAG: {flag}")
            # keep a copy of the winning render
            write_png(om, os.path.join(HERE, "artifacts", "qr.png"))
            return 0
    print("[-] QR did not decode")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
