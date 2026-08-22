# genie

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Miscellaneous |
| Author | ludicrouslytrue |
| Points | 138 |
| Solves at time of solving | 78 |
| Flag | `zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}` |

> do something with the bottle of the genie

Connection handout:

```console
$ ncat --ssl genie-<id>.chals.z0d1ak.org 1337
```

## Executive Summary

The handout is a Game Boy ROM and a custom "movie" format. The remote service
prints a 16-bit session seed, asks for one compact JSON movie, replays it on a
pristine seeded cartridge, and returns the flag only if the replay reaches the
ROM's `WIN` state.

The movie format includes a restricted cheat port: at most 12 little-endian
16-bit RAM writes, only in the windows `C100-C1FE` and `C300-C3FE`. That is the
intended attack surface.

Static reversing shows that the gold counter is protected by three
seed-dependent codewords:

```text
C100:C101 = gold
C102:C103 = gold XOR K(seed)
C104:C105 = MAC(seed, gold)
```

Changing only the gold word is repaired by the ROM, but writing all three words
in the same frame creates a valid authenticated balance. For the live seed
`2530`, the authenticated 5000-gold tuple was:

```text
C100 = 0x1388
C102 = 0x3506
C104 = 0x49ea
```

With 5000 gold in place, one START press calls the final-floor setup path
directly. The remaining lock is a small floor-9 "echo" state machine with three
selectors. Brute-forcing the three transforms gives the 9-selector sequence:

```text
2, 0, 2, 1, 2, 2, 0, 2, 1
```

The exploit submits 12 writes total: three for the authenticated 5000-gold
tuple, and nine for the echo selectors. The replay wins and the service returns:

```text
zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}
```

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/misc_genie.tar.gz`](challenge/misc_genie.tar.gz) | Original handout archive | `af41782ab39296794fece493cd9b9d5bd36050ba28aa7b11c900ecf6d6b85612` |
| [`challenge/seal.gb`](challenge/seal.gb) | Game Boy ROM, title `SEAL_NINTH` | `7521f2db4e8e9a5caeed3f0bfdb4993ed2abb21fe59f6084765919ae3b1f104c` |
| [`challenge/PORT.md`](challenge/PORT.md) | Official movie and cheat-port documentation | `d708bcedd56b4819ef72c04b0193758a137292eeb1c6209627aa6109fd7cd1d9` |
| [`solve.py`](solve.py) | End-to-end remote exploit and movie generator | - |
| [`verify_echo.py`](verify_echo.py) | Offline brute force for the 9-echo sequence | - |
| [`artifacts/live-session.txt`](artifacts/live-session.txt) | Captured solve transcript and live seed values | - |
| [`artifacts/reversing-notes.md`](artifacts/reversing-notes.md) | Address map and formula notes from ROM reversing | - |

Both Python scripts use only the standard library.

## 1. Triage

The archive contains two files:

```console
$ tar -tzf misc_genie.tar.gz
misc_genie/PORT.md
misc_genie/seal.gb

$ file seal.gb
seal.gb: Game Boy ROM image: "SEAL_NINTH" (Rev.01) [ROM ONLY], ROM: 256Kbit
```

`PORT.md` is more than a usage note. It defines the exact hosted replay format:

- the service prints `seed=<decimal>` and `movie-json>`;
- the submitted movie is JSON with `version`, `seed`, `joypad`, and `codes`;
- `joypad[n]` is the button mask for frame `n`;
- each cheat code is `[frame, address, value]`;
- only even addresses in `C100-C1FE` and `C300-C3FE` are accepted;
- at most 12 code writes are allowed.

The gameplay text also exposes the goal structure: floors 1 and 2 are normal,
floor 3 has a 5000-gold locked passage, and floor 9 has an "echo" interaction.
That tells us what to look for in RAM: a gold value, a final-floor marker, and a
small selector-driven state machine.

## 2. Reversing the Authenticated Gold Counter

The useful code sits in the lower ROM bank, and radare2 can disassemble the ROM
directly as Game Boy code:

```console
$ r2 -a gb -q seal.gb
```

The first important helper is `0x09f3`. It writes six bytes to `C100-C105`.
Given a desired 16-bit gold value in `DE`, it calculates and stores:

```text
C100:C101 = gold
C102:C103 = gold XOR K
C104:C105 = MAC(gold, K)
```

`K` is generated once during setup from the session seed. The helper at `0x04a5`
implements:

```python
K = ((0x3d29 + rol16(seed ^ 0xa5c3, 7)) & 0xffff) ^ 0x6b71
```

The MAC helper at `0x0578` implements:

```python
MAC = rol16(((0x6d2b + rol16(gold ^ K, 3)) & 0xffff) ^ rol16(K, 7), 5)
```

The frame loop calls a validator at `0x0a37`. It checks whether the current
`C100-C105` tuple is internally consistent. If not, it restores the last valid
tuple from the backup at `C400-C405`.

This is why a one-word "set gold to 5000" cheat does not survive. The winning
movie must write all three codewords atomically in one frame, before the CPU
runs that frame.

For the captured live seed:

```text
seed = 2530
K    = 0x268e
gold = 0x1388

C100 = 0x1388
C102 = 0x1388 XOR 0x268e = 0x3506
C104 = 0x49ea
```

Those are exactly the first three writes in the submitted movie.

## 3. Skipping to the Ninth Floor

The next useful path is the START handler in the main frame routine at
`0x0d73`.

When START is newly pressed, the ROM compares the authenticated gold word at
`C100:C101` against `0x1388` (5000). If it is lower, START is ignored for the
final passage. If it is at least 5000, the ROM calls `0x10aa`.

`0x10aa` is the final-floor setup routine. It:

1. subtracts 5000 gold using the same authenticated writer;
2. sets the floor marker `C406=0x09` and `C407=0xa9`;
3. resets the floor-9 vault state through `0x1084`;
4. draws the final room and the three echo hints.

So the first part of the movie is:

```text
frame 20:
  write C100 = 0x1388
  write C102 = 0x3506
  write C104 = 0x49ea
  press START
```

This reaches floor 9 without playing through floors 1-3 and without touching the
optional cursed-coin hazards.

## 4. Reversing the Echo Machine

On floor 9, pressing A does not immediately update the vault. It arms a pending
echo dispatch by setting:

```text
C300:C301 = 0x00fe
C40A      = 1
```

On the next frame, if `C40A` is set, the helper at `0x0efd` reads `C300:C301`.
If the word is `0`, `1`, or `2`, it dispatches through the table at `0x0f32`:

```text
selector 0 -> 0x109c
selector 1 -> 0x10a0
selector 2 -> 0x10a5
```

Those three tiny wrappers call `0x0ab2` with selector `0`, `1`, or `2`.
`0x0ab2` loads the current echo state from `C200:C201`, applies the selected
transform at `0x05ab`, writes the new state back, hashes it with `0x0599`, and
stores the hash in `C202:C203`.

The final readiness routine at `0x105d` compares that hash with two constant ROM
bytes:

```text
ROM[0x020f:0x0210] = 0x4a 0xb1
target hash        = 0xb14a
```

After final-floor setup, the echo state is reset to `0x1d0f`. Since the echo VM
has only three selectors, we can brute-force the transform graph offline. The
committed verifier reproduces the sequence:

```console
$ python3 verify_echo.py
length=9
sequence=2,0,2,1,2,2,0,2,1
state=0x120e
hash=0xb14a
```

The movie turns each selector into two frames:

1. press A to arm the echo handler;
2. release A and write the desired selector into `C300:C301`.

Only the second frame needs a cheat code, so all nine echoes fit exactly in the
remaining nine writes.

## 5. Building the Movie

The complete movie uses all 12 allowed writes:

```text
[20,  0xc100, 5000]      authenticated gold word 1
[20,  0xc102, gold ^ K]  authenticated gold word 2
[20,  0xc104, MAC]       authenticated gold word 3

[41,  0xc300, 2]
[53,  0xc300, 0]
[65,  0xc300, 2]
[77,  0xc300, 1]
[89,  0xc300, 2]
[101, 0xc300, 2]
[113, 0xc300, 0]
[125, 0xc300, 2]
[137, 0xc300, 1]
```

The corresponding non-zero joypad frames are:

```text
frame 20  START
frame 40  A
frame 52  A
frame 64  A
frame 76  A
frame 88  A
frame 100 A
frame 112 A
frame 124 A
frame 136 A
```

After the ninth echo, `C202:C203 == 0xb14a`, the ROM paints the persistent
`WIN / SUBMIT MOVIE / TO SERVICE / FOR FLAG` instruction, and the hosted replay
returns the actual flag.

## 6. Exploit

Run against any fresh instance:

```console
$ python3 solve.py genie-<id>.chals.z0d1ak.org 1337
WIN
zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}
```

The solver performs the following steps:

1. read `seed=<decimal>` from the TLS service;
2. derive `K(seed)`;
3. calculate the three authenticated 5000-gold codewords;
4. build the JSON movie with START and the nine echo selectors;
5. submit it as one compact JSON line.

To inspect the generated movie for a known seed without connecting:

```console
$ python3 solve.py --seed 2530
{"version":1,"seed":2530,"joypad":[...],"codes":[[20,49408,5000],...]}
```

The solved session is preserved in
[`artifacts/live-session.txt`](artifacts/live-session.txt).

## Root Cause

The challenge's "cheat port" is intentionally narrow, but the protected state is
still fully writable through that port:

- the gold value is authenticated, but all three authentication words are inside
  the writable `C100-C1FE` range;
- the final echo dispatch selector is inside the writable `C300-C3FE` range;
- the movie applies writes atomically before a frame runs, so the ROM never sees
  an inconsistent gold tuple.

That combination lets us satisfy the ROM's own checks instead of patching code
or relying on undefined emulator behavior.

## Lessons

- A checksum is not protection if both the data and the checksum are writable.
- Small state machines are perfect targets for offline search once their
  transition function and target state are known.
- For replay challenges, frame timing matters. The exploit works because the
  write happens before the frame executes, exactly as `PORT.md` specifies.
