# Reversing Notes

## Cartridge

`seal.gb` is a 32 KiB DMG Game Boy ROM:

```text
Game Boy ROM image: "SEAL_NINTH" (Rev.01) [ROM ONLY], ROM: 256Kbit
SHA-256: 7521f2db4e8e9a5caeed3f0bfdb4993ed2abb21fe59f6084765919ae3b1f104c
```

## Important RAM Fields

| Address | Meaning |
| --- | --- |
| `C0F0:C0F1` | session seed, little endian |
| `C100:C101` | authenticated gold value |
| `C102:C103` | gold XOR session key |
| `C104:C105` | gold authenticator/MAC |
| `C200:C201` | floor-9 echo state |
| `C202:C203` | hash of echo state |
| `C300:C301` | echo selector dispatch word |
| `C406:C407` | floor/phase marker; final floor is `09 a9` |
| `C408:C409` | seed-derived session key |
| `C40A` | pending echo dispatch flag |
| `C410:C411` | player tile position |
| `C412` | echo count |
| `C413` | collected optional-tile bitmask |
| `C414..C419` | three generated tile coordinate pairs |

## Seed-Derived Gold Authentication

The initial setup reads the service seed from `C0F0:C0F1`, calls the helper at
`0x04a5`, and stores the result in `C408:C409`.

```python
K = ((0x3d29 + rol16(seed ^ 0xa5c3, 7)) & 0xffff) ^ 0x6b71
```

Whenever the game intentionally changes gold, the helper at `0x09f3` writes a
three-word authenticated tuple:

```text
C100:C101 = gold
C102:C103 = gold ^ K
C104:C105 = rol16(((0x6d2b + rol16(gold ^ K, 3)) & 0xffff) ^ rol16(K, 7), 5)
```

The frame loop calls `0x0a37` to validate those three words. If only `C100` is
changed, the ROM restores the last valid tuple from `C400:C405`. Therefore the
movie must write all three words atomically in the same frame.

## Final-Floor Skip

The normal route reaches the expensive passage on floor 3. The important check
is simpler: when START is newly pressed, the frame handler compares the gold
word at `C100:C101` with `0x1388` (5000). If the value is at least 5000, it calls
`0x10aa`.

The `0x10aa` path:

- subtracts 5000 gold by calling the authenticated-gold writer;
- sets `C406=0x09` and `C407=0xa9`;
- resets the floor-9 state via `0x1084`;
- draws the final room.

So the exploit writes a valid 5000-gold tuple and presses START immediately.

## Echo VM

On floor 9, pressing A does not directly transform the state. It arms the echo
handler by setting:

```text
C300:C301 = 0x00fe
C40A      = 1
```

On the next frame, if `C40A` is set and `C300:C301` contains one of the accepted
selector words `0`, `1`, or `2`, the ROM dispatches through the table at
`0x0f32`:

```text
selector 0 -> 0x109c -> transform 0
selector 1 -> 0x10a0 -> transform 1
selector 2 -> 0x10a5 -> transform 2
```

All three paths call `0x0ab2`, which transforms the state in `C200:C201`, writes
the new state back, computes the hash at `C202:C203`, and increments `C412` on
the final floor.

The final readiness helper at `0x105d` checks:

```text
C406:C407 == 0x09a9
C202:C203 == ROM[0x020f:0x0210] == 0xb14a
```

Brute-forcing the three transforms from the reset state `0x1d0f` gives the
minimum sequence:

```text
2,0,2,1,2,2,0,2,1
```

After those nine echoes the state is `0x120e` and its hash is `0xb14a`, so the
ROM displays `WIN` and the service returns the flag.
