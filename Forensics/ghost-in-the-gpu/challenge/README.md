# Handout

The original handout, `ghost-in-the-gpu.zip` (30.5 MiB), is **not committed**.
`vram_dump.bin` is 32 MiB of cryptographically random filler with a single
1.5 MiB structured region, so the archive is incompressible and would add
30 MiB of permanent, undeltifiable weight to this repository's history for no
analytical benefit.

| File | Size | SHA-256 |
| --- | --- | --- |
| `ghost-in-the-gpu.zip` | 31,997,073 | `2b0d545e3a6c7d77954b01969feee5801ef7a261f8c51fa159455ccf8f8eeaf6` |
| `vram_dump.bin` | 33,554,432 | `efafbbcbdeab0f6b6d4f07c1ab74615e60f2ff815a5db067ebeda43f801a91b4` |

The analytically relevant part of the dump — bytes `0x00900000`–`0x00A80000`,
the surviving fp16 allocation — **is** committed, at
[`../artifacts/vram-region-0x900000.bin`](../artifacts/vram-region-0x900000.bin).
It holds only three distinct byte values, so it costs about 2.5 KiB once
zlib-compressed by git.

`solve.py` runs the complete pipeline (entropy scan → carve → decode) when
`vram_dump.bin` is placed in this directory, and automatically falls back to
the committed region when it is absent, so the decode is reproducible either
way.

```console
$ unzip ghost-in-the-gpu.zip -d Forensics/ghost-in-the-gpu/challenge/
$ python3 Forensics/ghost-in-the-gpu/solve.py
```
