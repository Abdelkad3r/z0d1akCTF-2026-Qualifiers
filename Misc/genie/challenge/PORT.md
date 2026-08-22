# Cartridge cheat port and movie format

Local experiments are unlimited. The **12-code limit applies only to the one
movie you submit**. A visual Game Boy emulator/debugger is required: open
`seal.gb` in BGB 1.6.6 or Emulicious. No headless emulator or local win oracle
is included in the handout.

The service gives you a 16-bit session seed. It changes cartridge data, not
code or addresses, so reverse the structure once in the emulator and adapt the
three seeded codeword values for the live session.

## Local game versus hosted submission

BGB or Emulicious is only the local gameplay and reversing laboratory. It does
not connect to the hosted instance, and neither emulator automatically exports
this challenge's complete JSON movie: debugger cheat writes must be transcribed
alongside the joypad frames.

When the movie is ready, connect to the generated TLS endpoint with a capable
client, for example:

```console
ncat --ssl HOST PORT
```

The service prints `seed=<decimal>` and `movie-json>`. Keep that connection
open, adapt the three seed-dependent gold words, and send the complete movie as
one compact JSON line. A successful replay replies with `WIN` and the only
scoreable flag. A new connection receives a new seed.

## Playing and debugging

The ROM is a normal DMG cartridge. The D-pad moves. On floors 1 and 2, collect
both the chest and monster, walk onto the visible gate in the lower-right, and
press START to spend 50 gold and advance. You may also hold START while taking
the final step onto an ordinary gate. Floor 3 is the final locked passage; its
displayed price is 5,000 gold. A operates the floor-9 echo.

Each normal floor also contains three optional cursed-coin tiles. Their
positions are selected deterministically from the session seed and floor. On
contact they deduct 7, 11, and 13 gold, respectively, then disappear for the
rest of that floor; all three reposition and become active on the next floor.
They are hazards, not gate objectives. The gold display updates immediately,
while `R` still depends only on the chest, monster, and current gate price.

The labeled HUD is `G00190 F2 P0050 R0E0`: `G` is gold, `F` is floor, `P` is
the current four-digit gate price, `R` is readiness, and `E` is the floor-9
echo count. On floors 1 and 2, `R` flips from 0 to 1 after both encounters are
cleared and the price is affordable; on floor 3 it reports whether the 5,000
gold final price is affordable; on floor 9 it is the ROM's vault comparison.
When the authenticated floor-9 seal is correct, the cartridge paints this
persistent instruction near the top of the room:

```text
WIN
SUBMIT MOVIE
TO SERVICE
FOR FLAG
```

The cartridge contains no local or demonstration flag. The hosted service is
the sole flag source and returns it only after replaying a winning movie; that
flag is not stored in the ROM. The reference movie ends with an explicit
neutral presentation-settle frame so the complete instruction is visible when
replay stops.

With BGB's default mapping, use the arrow keys, Enter for START, S for A, and
Esc for the debugger. The debugger's data viewer, cheat searcher, write
breakpoints, and disassembler are the intended local laboratory. BGB does not
export the complete service movie: manually author the JSON from the frame
inputs and cheat writes you determine during analysis.

## Cheat decoder

One code is `(frame, address, value)`:

- `frame` is zero based and must be in `0..3599`;
- `address` is an even 16-bit address;
- `value` is written little endian as one 16-bit word before that frame runs;
- accepted start addresses are `$C100-$C1FE` and `$C300-$C3FE`.

The decoder is deliberately narrower than the CPU's readable address space.
Debugger reads and ordinary Game Boy code can inspect all architectural RAM,
but the physical cheat connector is wired only to those two windows. A movie
containing an odd or out-of-window address is rejected, not ignored.

Codes for one frame are committed atomically in listed order, then the CPU runs
that frame. A frame is 70,224 SM83 clock cycles. At most 12 codes may appear in
the submitted movie.

## Joypad bits

The joypad byte uses `1 = pressed`:

| Bit | Button | Bit | Button |
|---:|---|---:|---|
| 0 | Right | 4 | A |
| 1 | Left | 5 | B |
| 2 | Up | 6 | Select |
| 3 | Down | 7 | Start |

## JSON movie

```json
{
  "version": 1,
  "seed": 4660,
  "joypad": [0, 16, 0, 0],
  "codes": [
    [1, 49408, 5000]
  ]
}
```

`joypad[n]` is the complete button mask for frame `n`; omitted trailing frames
are zero. The list may contain at most 3,600 entries. `codes` contains at most
12 triples. Decimal integers and quoted `0x` strings are accepted by the
service parser; ordinary JSON numeric literals are decimal.

The private service grader parses this format and replays it on the pristine
ROM. The handout deliberately has no Python replay command: construct the JSON
from what you observe and reverse in the external emulator, then submit it to
the service. The service returns the challenge's only flag after a successful
replay.
