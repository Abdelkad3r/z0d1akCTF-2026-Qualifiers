# Rewind

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Cryptography |
| Author | theg1239 |
| Points | 120 |
| Solves at time of solving | 138 |
| Flag | `zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}` |

> easy to slop

Connection handout:

```console
$ ncat --ssl rewind-<id>.chals.z0d1ak.org 1337
```

## Executive Summary

The service is a **stream cipher** that reuses the same keystream for every
encryption in a session — the counter that should advance is "rewound" to the
same starting value each time. The banner hands us `secret_ct`, the flag
encrypted under that keystream, and the menu exposes an oracle that will encrypt
**attacker-controlled bytes under the very same keystream**.

That is a textbook **two-time pad / keystream-reuse** break. For a stream cipher
`ct = pt ⊕ keystream`. Ask the oracle to encrypt a block of zero bytes and it
hands the keystream straight back:

```
enc(0x00…) = 0x00… ⊕ keystream = keystream
```

XOR that keystream against `secret_ct` and the flag falls out. No key, no nonce,
and no cryptanalysis of the underlying cipher are ever needed.

```
secret_ct = c50ccaacbdb7ccf995d89847efd1bcf9ea3c9981315ec3ca3ae6a1dcddabb095f9700de99eece96c6e72689a
keystream = bf68a1d7efd29b95fb9cf109888ec891af63dab16410b7f948b9d39988d883e6a62465dac19fbd3e2b4605e7
flag      = secret_ct ⊕ keystream
          = zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}
```

The flag spells out the lesson: rewinding the counter reuses the stream.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end remote exploit (connect → recover keystream → XOR → flag) |
| [`verify_offline.py`](verify_offline.py) | Offline reproduction from the captured hex — no network needed |
| [`artifacts/session-transcript.txt`](artifacts/session-transcript.txt) | Exact TLS session used to solve, client input annotated |
| [`artifacts/secret_ct.hex`](artifacts/secret_ct.hex) | The flag ciphertext from the banner (44 bytes) |
| [`artifacts/keystream.hex`](artifacts/keystream.hex) | Recovered keystream, i.e. `enc(0x00 × 44)` (44 bytes) |
| [`artifacts/derivation.txt`](artifacts/derivation.txt) | Byte-by-byte `secret_ct ⊕ keystream = flag` table |

Because the challenge is an **instancer** (each launch spins up a fresh,
short-lived `rewind-<id>.chals.z0d1ak.org`), the live host in the handout is
ephemeral. The captured `secret_ct`/`keystream` pair and `verify_offline.py`
make the solve reproducible after the instance is gone; `solve.py` re-runs the
full attack against any fresh instance.

## 1. Reconnaissance

Connecting over TLS presents a banner and a three-option menu:

```
The operator swears the stream is fresh every time.
Watch what happens when the counter keeps rewinding.

secret_ct = c50ccaacbdb7ccf995d89847efd1bcf9ea3c9981315ec3ca3ae6a1dcddabb095f9700de99eece96c6e72689a

[1] Show encrypted token
[2] Encrypt attacker-controlled bytes (hex)
[3] Exit
>
```

Three facts stand out:

- **`secret_ct` is 92 hex chars = 44 bytes** — the target ciphertext, printed up
  front. Its length equals the plaintext length (a hallmark of a stream cipher /
  XOR keystream, not a block cipher with padding).
- **Option `[2]` is an encryption oracle** for arbitrary bytes.
- The prose is the entire hint. *"The operator swears the stream is fresh every
  time"* is the buggy assumption; *"Watch what happens when the counter keeps
  rewinding"* tells us the counter/keystream is **reset to the same value for
  every encryption** rather than advancing. Same key + same counter ⇒ same
  keystream ⇒ two-time pad.

## 2. Why Keystream Reuse Is Fatal

A stream cipher encrypts by XOR-ing plaintext with a pseudorandom keystream
derived from `(key, nonce/counter)`:

```
ct = pt ⊕ KS(key, counter)
```

Security depends entirely on **never** producing the same keystream twice under
the same key. Here the counter "rewinds", so the keystream `KS` is identical for
`secret_ct` and for anything we submit to option `[2]`. Given two ciphertexts
under the same keystream, `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`, and the keystream cancels. We
don't even need that general form: we control one plaintext completely, so we can
make it all zeros and read the keystream directly.

## 3. Recovering the Keystream

Send option `[2]` and supply 44 zero bytes (matching the 44-byte `secret_ct`):

```
> 2
hex plaintext > 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
ct = bf68a1d7efd29b95fb9cf109888ec891af63dab16410b7f948b9d39988d883e6a62465dac19fbd3e2b4605e7
```

Since `pt = 0x00…`, the returned ciphertext **is** the keystream:

```
enc(0x00 × 44) = 0x00 × 44 ⊕ keystream = keystream
```

The full annotated session is in
[`artifacts/session-transcript.txt`](artifacts/session-transcript.txt).

## 4. Recovering the Flag

XOR the recovered keystream against `secret_ct`:

```python
secret_ct = bytes.fromhex("c50ccaacbdb7ccf995d89847efd1bcf9ea3c9981315ec3ca3ae6a1dcddabb095f9700de99eece96c6e72689a")
keystream = bytes.fromhex("bf68a1d7efd29b95fb9cf109888ec891af63dab16410b7f948b9d39988d883e6a62465dac19fbd3e2b4605e7")
flag = bytes(a ^ b for a, b in zip(secret_ct, keystream))
# b'zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}'
```

Every byte lands in printable ASCII and the string is well-formed
(`zdk{…}`), which is the sanity check that the keystream alignment is correct.
The byte-by-byte derivation is committed in
[`artifacts/derivation.txt`](artifacts/derivation.txt):

```
  i  sec   ks  xor  ascii
------------------------------
  0   c5   bf   7a   z
  1   0c   68   64   d
  2   ca   a1   6b   k
  3   ac   d7   7b   {
  ...
 43   9a   e7   7d   }
```

```
zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}
```

## 5. Reproducing

Against a fresh instance (the exploit auto-sizes the zero block to the printed
`secret_ct` length and retries a flaky instancer):

```console
$ python3 solve.py rewind-<id>.chals.z0d1ak.org 1337
...
[*] recovered keystream: bf68a1d7…4605e7
[+] FLAG: zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}
```

Offline, from the committed capture (no network, instance-independent):

```console
$ python3 verify_offline.py
[+] zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}
```

Both are dependency-free (Python standard library only).

## Root Cause and Fix

- **Root cause:** the keystream counter/nonce is reset ("rewound") to a fixed
  value for every encryption under the same key, so `secret_ct` and every oracle
  response share one keystream. Exposing an encryption oracle under that reused
  keystream turns the secret into a trivial two-time-pad recovery.
- **Fix:** never reuse a `(key, nonce)` pair. Draw a fresh random nonce per
  message and advance the counter monotonically, or use a misuse-resistant AEAD
  (e.g. AES-GCM-SIV) so a nonce slip degrades gracefully instead of leaking
  plaintext. And do not offer an encryption oracle over the same keystream that
  protects a secret.

## Lessons

- **A reused keystream is not encryption — it's a mask you can subtract.** With
  one chosen plaintext (zeros) the keystream is handed to you outright.
- **Length equal to plaintext + an encrypt-anything oracle = two-time pad.**
  Recognize the shape before touching the underlying cipher; the primitive never
  matters once the stream repeats.
- **Read the flavortext literally.** "The counter keeps rewinding" was a precise
  description of the bug, and the flag itself states it: rewinding the counter
  reuses the stream.
