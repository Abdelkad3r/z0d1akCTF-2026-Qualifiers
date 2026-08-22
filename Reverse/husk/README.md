# husk

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Reverse Engineering |
| Author | Abhi404 |
| Points | 132 |
| Solves at time of solving | 91 |
| Flag | `zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}` |

> Every shell you peel off is just another shell.

## Executive Summary

`husk` is a small (14 KB) stripped x86-64 PIE that validates a single 41-byte
argument. The "shells you peel off" are four **anti-debug checks** — and the
twist, which the flag states outright, is that *the anti-debug results **are** the
decryption key*. In a clean run each check returns `0`, so the whole validator is
deterministic; attach a debugger (or `LD_PRELOAD`) and the derived key changes,
silently corrupting the comparison.

The check is:

```
accept  iff  F( input ⊕ LCG )  ==  RC4_keystream(key) ⊕ CONST_B
```

- **key** (16 bytes) is assembled from the four anti-debug results XORed with
  fixed constants; clean run ⇒ `de c0 37 13 b5 00 6b b1 ce fa ed fe be ba fe ca`.
- **CONST_B** is derived from two rodata tables.
- **LCG** is a fixed linear-congruential keystream (seed `0x1234abcd`).
- **F** is a 6-round, byte-oriented, chained cipher (two rotate/add/XOR passes
  plus a mod-41 permutation per round).

Every layer is a bijection, so the flag is recovered by inverting the pipeline:

```
flag = LCG ⊕ F⁻¹( RC4_keystream(key) ⊕ CONST_B )
     = zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}
```

("the antidebug was the decryption key.")

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | Reimplements every layer, computes `EXPECTED`, inverts `F`, prints the flag (and re-verifies forward) |
| [`artifacts/derivation.txt`](artifacts/derivation.txt) | Recovered constants, the RC4 key, `CONST_B`, `EXPECTED`, and the LCG buffer |
| [`artifacts/husk-check-disasm.txt`](artifacts/husk-check-disasm.txt) | Full annotated `.text` disassembly of the validator |
| [`challenge/husk`](challenge/) | The original binary |
| [`challenge/rev_husk.zip`](challenge/) | Original handout |

Pure-Python, no third-party dependencies; the binary itself is not executed.

## 1. Triage

```
$ file husk
husk: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
$ strings husk | grep -Ei 'ptrace|status|preload|correct|nope'
/proc/self/status   TracerPid:   LD_PRELOAD   Nope   Correct!
```

Imports are the giveaway: `ptrace`, `open`/`read` (for `/proc/self/status`),
`getenv` (for `LD_PRELOAD`), plus `strtoul`/`strstr`. The `.text` is only ~2 KB,
so the entire validator is one function; it prints `usage: %s <flag>`, then
`Correct!` / `Nope`.

## 2. Peeling the anti-debug shells

Four checks each compute a 32-bit value and XOR it into a 16-byte buffer that
becomes the key. Reading the disassembly, in a **clean run** every check yields
`0`:

| Check | Instruction | Clean result | Stored value |
| --- | --- | --- | --- |
| `ptrace(PTRACE_TRACEME)` | `xor eax, 0x1337c0de` | `0` | `0x1337c0de` |
| `TracerPid:` in `/proc/self/status` | `xor eax, 0xb16b00b5` | `0` | `0xb16b00b5` |
| `rdtsc` timing of a 200-iter loop | `xor eax, 0xfeedface` | `0` | `0xfeedface` |
| `getenv("LD_PRELOAD")` | `xor eax, 0xcafebabe` | `0` | `0xcafebabe` |

Under a debugger `ptrace` returns `-1`, `TracerPid` is non-zero, single-stepping
blows the `rdtsc` budget, and an `LD_PRELOAD` shim flips the last check — each
would change the key and break decryption. That is the whole trick: **the checks
don't just gate execution, they *are* the key material.**

The four dwords (little-endian) form the key:

```
de c0 37 13  b5 00 6b b1  ce fa ed fe  be ba fe ca
```

## 3. The expected value

```
CONST_B[i] = table1[(0x11*i) mod 41] ⊕ table2[i mod 16]      # two rodata tables
EXPECTED   = RC4_keystream(key)[0:41] ⊕ CONST_B
```

- `table1` (41 bytes @ `0x206c`), `table2` (16 bytes @ `0x20a0`).
- RC4 is textbook: S-box initialised `0..255` (vectorised), KSA keyed by the
  16-byte anti-debug key, PRGA producing 41 bytes.

`EXPECTED` is what the transformed input must equal.

## 4. The input transform `F`

The argument is first whitened: `input ⊕ LCG`, where `LCG[i]` is the top byte of
a `state = state*0x41c64e6d + 0x3039` sequence seeded at `0x1234abcd`.

Then a **6-round** loop (the counter starts at 0 and the loop exits when it
reaches 6, so rounds `0..5` execute — *not* seven). Each round, on the 41-byte
buffer, does three invertible passes:

1. **Forward chained pass** — `out1[i] = rol8(state, c2) ⊕ rol8((in[i] + 0x1d·i +
   r10) & 0xff, c1)`, `state = out1[i]`; rotate amounts are `(round+i)%7+1` and
   `(r11+i)%7+1`; the per-round constants `r9,r10,r11` advance by fixed steps.
2. **Reverse chained pass** — over `i = 0x28…0`, another rotate/XOR/add chain
   feeding `out2`.
3. **Permutation** — `out3[(5·round + 7·i) mod 41] = out2[i]`.

Crucially, **`F` does not use the anti-debug key** — only `EXPECTED` does. That
lets `F` be validated independently of any debugger state.

## 5. Inverting the pipeline

Everything is a bijection over `GF(2⁸)⁴¹`, so:

```python
buf = EXPECTED
for rnd in range(5, -1, -1):     # undo rounds 5..0
    buf = inv_round(buf, rnd)    # un-permute -> un-reverse-pass -> un-forward-pass
flag = bytes(a ^ b for a, b in zip(buf, LCG))
```

Each `inv_round` reverses the permutation, then walks the two chained passes in
their original order undoing rotate/add/XOR (the chain state is simply the
previous output byte). Running the *forward* `F` on the recovered flag reproduces
`EXPECTED` exactly — a self-check that the reimplementation is correct.

```console
$ python3 solve.py
env_key   : dec03713b5006bb1cefaedfebebafeca
EXPECTED  : e722f9f7...651b460b65
recovered flag: b'zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}'
forward(flag)==EXPECTED: True
```

```
zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}
```

## 6. A note on the intended approach

Because the key is the anti-debug output, the *dynamic* shortcut fails: attach
gdb to read the answer and `ptrace`/`TracerPid`/timing flip, so the program
derives a **different** key and never reveals the plaintext. The clean solve is
static — recognise that each check yields a constant in a normal run, then invert
the deterministic transform. (If you do use a debugger, note that `F` itself is
key-independent, so you can still verify your `F` reimplementation dynamically and
compute `EXPECTED` from the debugger-observed key separately.)

## Lessons

- **Anti-debug as key derivation.** When tamper checks feed the crypto instead of
  branching to "exit", patching them out changes the result rather than bypassing
  it. Read them; don't nop them.
- **Count your loops.** The 6-vs-7 round off-by-one is the classic reversing trap:
  the exit test runs *after* the increment, so the last index never executes.
- **Bijections invert.** Rotations, additions, XORs, and permutations are all
  reversible; a chained cipher yields to a careful round-by-round inverse, and the
  forward re-check confirms it.
