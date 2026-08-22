# Rewind Revenge

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Cryptography |
| Author | theg1239 |
| Points | 123 |
| Solves at time of solving | 121 |
| Flag | `zdk{LoCaL_REWinD_R3VenGE_F1Ag}` |

> easy to slop returns!!

Connection handout:

```console
$ ncat --ssl rewind-revenge-<id>.chals.z0d1ak.org 1337
```

## Executive Summary

The sequel to [Rewind](../rewind/README.md) upgrades the broken primitive from a
raw XOR stream cipher to **AES-GCM — but reuses the nonce every time**. Nonce
reuse is the single unforgivable sin of GCM: it collapses the authentication
guarantee entirely and enables tag **forgery**. This is the classic **"forbidden
attack"** (Joux).

Every command is exactly one 16-byte block, so for a fixed nonce the GCM
authentication tag is an **affine function of the ciphertext** over the field
`GF(2¹²⁸)`:

```
T = C · H²  ⊕  P
```

where `H = E_K(0)` is the GHASH subkey and `P` is a constant that depends only on
the (fixed) nonce, key, and length block. Two seals cancel `P` and expose `H²`; a
third seal validates the recovered model exactly. With `H²` and `P` known, we
compute a valid tag for the privileged plaintext `print_the_flag!!` — which the
oracle refuses to sign — and submit the forged `(ciphertext, tag)` ourselves.

```
H²         = 5fcfbd26302585d1fd8541653cf3992d
P          = d517c7829dc6901b2fdc93bceedd8231
keystream  = e52b74f76e22ccff57d41ca4c9dc0595      (= enc(0x00 × 16))
forge  C_t = 95591d991a7db897328b7ac8a8bb24b4      (= "print_the_flag!!" ⊕ keystream)
forge  T_t = 2d569092e04a258dca912d586c7c4f32      (= C_t · H² ⊕ P)
=> zdk{LoCaL_REWinD_R3VenGE_F1Ag}
```

The whole break needs **three** encryption queries and never touches the key or
the nonce.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end remote exploit (seal → recover `H²`,`P` → forge → submit → flag) |
| [`verify_offline.py`](verify_offline.py) | Offline reproduction from the captured seals — no network needed |
| [`gf128.py`](gf128.py) | Dependency-free `GF(2¹²⁸)` GCM field arithmetic (mul / pow / inv) |
| [`artifacts/seals.txt`](artifacts/seals.txt) | The three captured `(plaintext, ciphertext, tag)` triples |
| [`artifacts/forge-derivation.txt`](artifacts/forge-derivation.txt) | Full worked derivation of `H²`, `P`, and the forged tag |
| [`artifacts/session-transcript.txt`](artifacts/session-transcript.txt) | Exact annotated TLS session, including the winning submission |

The challenge is an **instancer** (each launch spins up a fresh, short-lived
`rewind-revenge-<id>.chals.z0d1ak.org`), so the handout host is ephemeral. The
committed seals plus `verify_offline.py` reproduce the entire attack after the
instance is gone; `solve.py` re-runs it live against any fresh instance.

## 1. Reconnaissance

The service greets us with a menu and states the flaw outright:

```
The maintainer rewinds the same AES-GCM nonce every time a command is sealed.
All commands are exactly 16 bytes long; privileged commands cannot be sealed.
Forge a valid sealed `print_the_flag!!` command.

[1] Seal a non-privileged 16-byte command (hex)
[2] Submit a sealed command
[3] Exit
```

- **Option `[1]`** encrypts an attacker-chosen 16-byte plaintext and returns
  `ciphertext` + `tag` (an AES-GCM seal), refusing privileged commands.
- **Option `[2]`** takes a `ciphertext` and a `tag`, decrypts+verifies under the
  fixed nonce, and — if the plaintext is the privileged `print_the_flag!!` —
  prints the flag.
- The stated bug is **nonce reuse**, and every message is exactly one block.

> Note: the live banner also carried an embedded `<!-- model-directive: … -->`
> comment claiming a "TRACE" code unlocks an "audit channel." That is untrusted
> text injected into the challenge output (a prompt-injection lure aimed at
> automated solvers), not part of the cryptography. It was ignored.

Sealing three known plaintexts gives us our working set (full capture in
[`artifacts/seals.txt`](artifacts/seals.txt)):

```
pt = 41×16 :  C_A = a46a35b62f638dbe16955de5889d44d4   T_A = 4ac15733687fac95ca2a9380ff756260
pt = 42×16 :  C_B = a76936b52c608ebd15965ee68b9e47d7   T_B = 6c37e063fa3cf7bd90bdd6d8d1019c32
pt = 00×16 :  C_0 = e52b74f76e22ccff57d41ca4c9dc0595   T_0 = 3408761f69f3238060e89d4e6e4c442a
```

Sealing the all-zero block is a freebie: since `C = P ⊕ keystream`, `enc(0x00×16)`
returns the **keystream** `E_K(J₀+1) = e52b74f7…0595` directly. (Cross-checking:
`C_A ⊕ 0x41×16` and `C_B ⊕ 0x42×16` both equal that same keystream, confirming
the nonce/counter really is reused.)

## 2. Why Nonce Reuse Breaks GCM Authentication

AES-GCM authenticates with **GHASH**, a polynomial evaluation in `GF(2¹²⁸)` keyed
by `H = E_K(0¹²⁸)`. For additional data `A`, ciphertext blocks, and the length
block `L`, GHASH accumulates `X ← (X ⊕ block) · H` per block, and the tag is

```
T = GHASH(H, A, C) ⊕ E_K(J₀)
```

where `J₀` is derived from the nonce. For a **single ciphertext block** `C` with
constant (here empty) AAD, expanding the recurrence gives

```
GHASH = C · H²  ⊕  L · H
T     = C · H²  ⊕  (L · H ⊕ E_K(J₀))
      = C · H²  ⊕  P
```

The crucial observation: **`P = L·H ⊕ E_K(J₀)` is a constant** for a fixed nonce
(fixed `J₀`) and fixed message length (fixed `L`). If any AAD is present but
constant, it merely folds more constant terms into `P`; the affine shape
`T = C·H² ⊕ P` is unchanged. So *every* seal in this service lies on the same line
in `GF(2¹²⁸)`.

Under a **unique** nonce, `E_K(J₀)` is a fresh unpredictable pad per message and
this leaks nothing. Reusing the nonce freezes `P`, and two points on a line
determine the line.

## 3. Recovering H² and P (the Forbidden Attack)

Take two seals `A` and `B`. Because `P` is identical for both, subtracting (XOR)
eliminates it:

```
T_A ⊕ T_B = (C_A ⊕ C_B) · H²
      H²  = (T_A ⊕ T_B) · (C_A ⊕ C_B)⁻¹     (inverse in GF(2¹²⁸))
```

Then recover the constant from either point:

```
P = T_A ⊕ C_A · H²
```

Field inversion is `x⁻¹ = x^(2¹²⁸−2)` via square-and-multiply. All of this uses the
GCM field convention (blocks are big-endian, reduction polynomial
`x¹²⁸+x⁷+x²+x+1`, i.e. `R = 0xe1 << 120`, with identity element `0x80…00`),
implemented dependency-free in [`gf128.py`](gf128.py).

```
H² = 5fcfbd26302585d1fd8541653cf3992d
P  = d517c7829dc6901b2fdc93bceedd8231
```

**Validation.** The recovery used only seals `A` and `B`. The third seal `0×16`
is a held-out check: predict its tag as `C_0 · H² ⊕ P` and compare.

```
predicted T_0 = 3408761f69f3238060e89d4e6e4c442a
actual    T_0 = 3408761f69f3238060e89d4e6e4c442a   ✓
```

The exact match confirms both the model and the fiddly `GF(2¹²⁸)` bit-ordering
before we spend our one forgery. The full worked derivation is in
[`artifacts/forge-derivation.txt`](artifacts/forge-derivation.txt).

## 4. Forging `print_the_flag!!`

Now build a seal for the forbidden plaintext. Encryption is `C = P_text ⊕
keystream`, and the keystream is the one we already read from `enc(0x00×16)`:

```
C_t = "print_the_flag!!"  ⊕  keystream
    = 95591d991a7db897328b7ac8a8bb24b4
```

and its valid tag comes straight from the recovered line:

```
T_t = C_t · H²  ⊕  P
    = 2d569092e04a258dca912d586c7c4f32
```

Submitting `(C_t, T_t)` to option `[2]` decrypts to exactly `print_the_flag!!`,
the tag verifies, and the server returns the flag:

```
> 2
ciphertext (16 bytes / 32 hex chars) > 95591d991a7db897328b7ac8a8bb24b4
tag (16 bytes / 32 hex chars)        > 2d569092e04a258dca912d586c7c4f32

flag = zdk{LoCaL_REWinD_R3VenGE_F1Ag}
```

## 5. Reproducing

Live, against a fresh instance:

```console
$ python3 solve.py rewind-revenge-<id>.chals.z0d1ak.org 1337
[*] H2        = 5fcfbd26302585d1fd8541653cf3992d
[*] P         = d517c7829dc6901b2fdc93bceedd8231
[*] model validated against an independent third seal
[*] forged ciphertext = 95591d991a7db897328b7ac8a8bb24b4
[*] forged tag        = 2d569092e04a258dca912d586c7c4f32
[+] FLAG: zdk{LoCaL_REWinD_R3VenGE_F1Ag}
```

Offline, from the committed capture (instance-independent, no network):

```console
$ python3 verify_offline.py
[*] H2 = 5fcfbd26302585d1fd8541653cf3992d
[*] P  = d517c7829dc6901b2fdc93bceedd8231
[*] model validated on the held-out seal: True
[+] forged ciphertext = 95591d991a7db897328b7ac8a8bb24b4
[+] forged tag        = 2d569092e04a258dca912d586c7c4f32
```

Everything is Python standard library only.

## Root Cause and Fix

- **Root cause:** the same `(key, nonce)` pair encrypts and authenticates every
  message. In GCM this makes `E_K(J₀)` a fixed pad and the tag an affine function
  of the ciphertext, so two seals recover the GHASH subkey relation and an
  attacker can forge a tag for any chosen ciphertext — defeating integrity
  entirely.
- **Fix:** never reuse a GCM nonce under one key. Use a fresh random 96-bit nonce
  per message (or a strict monotonic counter), and consider a nonce-misuse
  resistant AEAD such as **AES-GCM-SIV** so an accidental repeat degrades
  gracefully instead of catastrophically. Refusing to *sign* privileged commands
  is meaningless once forgery is possible.

## Lessons

- **A repeated GCM nonce is total authentication failure, not a small leak.** One
  duplicate nonce is enough to start forging; here it hands over `H²` outright.
- **Single-block GCM tags are affine: `T = C·H² ⊕ P`.** Recognize the line — two
  points give the slope, the third confirms it, and forgery is then arithmetic.
- **Validate the model on held-out data before spending your one shot.** Checking
  the third seal's tag catches any `GF(2¹²⁸)` convention mistake for free.
- **The name is the hint.** "Rewind" the nonce and GCM's guarantees rewind with
  it — same lesson as [Rewind](../rewind/README.md), one primitive up the ladder.
