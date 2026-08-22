# siren

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Cryptography |
| Author | Abhi404 |
| Points | 116 |
| Solves at time of solving | 171 |
| Flag | `zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}` |

> The Siren will sing any sailor's words back to him, sealed in her own hand.
> There is only one phrase she will never voice: the phrase that lifts the tide
> gate over her hoard. Give her enough verses and the silence in every breath
> spells her name.

## Executive Summary

The service is an ECDSA (secp256k1) signing oracle. It will sign any message
except the one that unlocks the flag, `unlock:release-the-tide`; sending back a
valid signature for that message returns the flag.

The private key never has to be attacked head-on, because the nonce generation
is broken. For every signature the top **10 bits of the nonce are fixed to a
public, attacker-computable value** — `public_pitch(msg)`, the high bits of
`sha256(song_id + ":" + msg)`, and the server hands us `song_id`. A biased/known
nonce is the classic setup for the **Hidden Number Problem**: collect a few
dozen signatures, feed the leaked bits into a lattice, and LLL recovers the
private key `D`. With `D` known, forging a signature for the forbidden message is
trivial. The Siren's refusal to *sign* that phrase is irrelevant — we sign it
ourselves.

The [solver](solver/solve_remote.py) does this end to end. Against a live
instance it recovered the key and unlocked the flag:

```
[*] The Siren hums on the rocks. Send her a line to sign.
[*] song_id=088bc8285ac3a26d priv_msg='unlock:release-the-tide'
[*] collected 45 signatures
[*] key recovery: 73.4s -> OK
[+] D = 188e2c7f6dcb7ead4f76ffaf053f684f2a5e4841afa8032d2b10a850feb18b6e
[+] unlock: {'flag': 'zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}'}
```

The attack is also validated offline against a simulator of the exact server
signer ([`test_local.py`](solver/test_local.py)): a clean 5/5 key recovery at 40
signatures.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/siren_server.py`](challenge/siren_server.py) | Original server handout | `69fe9267131f7c7819726f4cffbdea6d48e2f965e104bdfca997f9eac5c639e1` |
| [`solver/solve_remote.py`](solver/solve_remote.py) | End-to-end remote exploit (collect → recover → forge → unlock) | — |
| [`solver/attack.py`](solver/attack.py) | HNP lattice construction and key recovery | — |
| [`solver/ec.py`](solver/ec.py) | Dependency-free secp256k1 (point ops, scalar mult) | — |
| [`solver/lll.py`](solver/lll.py) | LLL — fpylll if available, pure-python integer-LLL fallback | — |
| [`solver/test_local.py`](solver/test_local.py) | Offline self-test against a simulated signer | — |

The original archive `crypto_siren (1).tar.gz` has SHA-256
`a26a331ae1a21c5d3834b9110d42a3bcf54161ed32b043c405b97df3cf378fe6`.

## 1. Understanding the Service

The oracle speaks newline-delimited JSON over TLS and exposes three commands:

- `pubkey` → the public key `Q`, curve order `n`, the per-instance `song_id`,
  `pitch_bits`, and `priv_msg`.
- `sign{msg}` → an ECDSA signature `(r, s)` for any `msg` **except** `priv_msg`.
- `unlock{r,s}` → returns the flag iff `(r, s)` verifies for `priv_msg`.

Standard ECDSA otherwise: `z = H(msg)`, `s = k⁻¹(z + rD) mod n`, `r = (kG).x mod
n`. The only unusual part is how the nonce `k` is produced:

```python
PITCH_BITS  = 10
SUFFIX_BITS = 256 - PITCH_BITS          # 246

def public_pitch(msg):
    material = (SONG_ID + ":" + msg).encode()
    h = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return h >> (256 - PITCH_BITS)      # top 10 bits of the hash

def shaped_nonce(msg):
    prefix = public_pitch(msg) << SUFFIX_BITS
    while True:
        k = prefix | (rng_below(SUFFIX_BOUND) - 1)   # low 246 bits random
        if 1 <= k < N:
            return k
```

So every nonce is `k = prefix | random246`, and **`prefix` is public**: it is
determined entirely by `song_id` (given to us) and `msg` (chosen by us). In other
words, **the top 10 bits of every signing nonce are known to the attacker.** This
is exactly the "silence in every breath" the prompt hints at — the fixed
high-bit pattern of each nonce.

## 2. From Known Nonce Bits to the Hidden Number Problem

For each signature `i`, the ECDSA relation gives the nonce as a function of the
private key `D`:

```
k_i = s_i⁻¹ (z_i + r_i · D)   (mod n)
```

We know the top 10 bits of `k_i`, i.e. `a_i = public_pitch(msgᵢ) << 246`, and the
remainder `e_i = k_i − a_i` is small: `0 ≤ e_i < 2²⁴⁶`. Substituting and writing

```
t_i = r_i · s_i⁻¹ (mod n)        u_i = z_i · s_i⁻¹ (mod n)
```

yields, for every signature, a linear congruence in the single unknown `D` with a
small "error":

```
t_i · D + (u_i − a_i)  ≡  e_i   (mod n),      0 ≤ e_i < 2²⁴⁶
```

This is the **Hidden Number Problem**: recover `D` given many `(t_i, c_i)` where
`t_i·D + c_i` is known to be small modulo `n`. Each signature pins ~10 bits of
`D`, so `⌈256/10⌉ ≈ 26` signatures suffice in principle; the solver uses ~40–45
for a comfortable lattice margin.

## 3. The Lattice Attack

Center the errors about `B/2` (with `B = 2²⁴⁶`) so they are symmetric, and build
the standard HNP lattice of dimension `m + 2` (for `m` signatures):

```
        col 0 … col m-1      col m (D)   col m+1 (target)
row i   [   N·K on diag  ]       0             0            (i = 0 … m-1)
row m   [  t_0·K … t_{m-1}·K ]   1             0
row m+1 [ c'_0·K … c'_{m-1}·K ]  0            B/2·K
```

where `c'_i = (u_i − a_i − B/2) mod n`. The key detail is the column weighting:
the `D`-marker column has weight 1 while the others are scaled by `K = 2¹⁰`, so
that `D·1 ≈ 2²⁵⁶` is *comparable in size* to `K·e_i ≈ 2²⁵⁶`. Without this
balancing the `D` coordinate (or a fractional `B/n` weight) dominates and the
solution is not the shortest vector.

The lattice vector formed with `x = D` and the target row used once is

```
( K·e'_0, …, K·e'_{m-1},  D,  K·B/2 )
```

which is roughly `2¹⁰ ×` shorter than the plain `N·K` basis rows, so **LLL
surfaces it**. From any recovered centered error `e'_i` we reconstruct the nonce
`k_i = a_i + e'_i + B/2` and read the private key straight off the ECDSA relation:

```
D = (s_i · k_i − z_i) · r_i⁻¹   (mod n)
```

Each candidate is confirmed by the public-key check `D·G == Q`, which makes the
recovery self-verifying and robust to any sign/coordinate ambiguity in the
reduced basis.

## 4. Forging the Unlock

With `D` in hand, signing the forbidden message is ordinary ECDSA — no oracle
needed:

```python
z = H("unlock:release-the-tide")
k = random_nonce()
r = (k·G).x mod n
s = k⁻¹ (z + r·D) mod n
```

Sending `unlock{r, s}` passes `verify(PRIV_MSG, r, s)` and the server returns the
flag.

```
zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}
```

The flag states the lesson outright: *a few bits per signature sinks the key.*

## 5. Reproducing

The remote exploit is dependency-light and takes the instance host as an
argument (the challenge is an **instancer**, so each launch gets a fresh
`siren-<id>.chals.z0d1ak.org`):

```console
$ python3 solver/solve_remote.py siren-<id>.chals.z0d1ak.org 1337
```

Offline validation against a simulator of the exact signer requires no network:

```console
$ python3 solver/test_local.py 40 5
trial 0: RECOVERED (…s)
...
success 5/5
```

Notes on the reduction backend:

- `lll.py` uses **fpylll** when importable (fast and numerically robust) and
  otherwise falls back to a **pure-python fraction-free integer LLL**, so the
  code runs with zero third-party dependencies at the cost of speed on larger
  dimensions.
- Give the lattice enough rows: with a 10-bit leak, fewer than ~26 signatures is
  information-theoretically insufficient and recovery will fail regardless of the
  reducer. The solver defaults to 45.

## Root Cause and Fix

- **Root cause:** the nonce is not uniform. Fixing its top 10 bits to a public
  value leaks 10 bits of `k` per signature, and ECDSA nonce leakage is fatal —
  even a handful of bits across enough signatures recovers the private key via
  lattice reduction.
- **Fix:** generate nonces uniformly at random in `[1, n)`, or derive them
  deterministically per RFC 6979 from the key and message. The nonce must be
  secret and unbiased in *every* bit; there is no safe amount of structure to
  expose.

## Lessons

- **A biased nonce is a broken nonce.** "Only 10 known bits" sounds harmless; it
  is a full key-recovery primitive once the leak is systematic across signatures.
- **Recognize the HNP shape.** Any time a secret satisfies `t·D + c ≈ 0 (mod n)`
  with a small, bounded error you can compute, reach for a lattice.
- **Make recovery self-verifying.** Checking each candidate `D` against `D·G == Q`
  turns a finicky lattice/sign bookkeeping problem into a robust search.
