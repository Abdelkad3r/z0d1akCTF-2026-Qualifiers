# cyclotomic-echo

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Cryptography |
| Author | afish |
| Points | 139 |
| Solves at time of solving | 76 |
| Flag | `zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}` |

> Some keys disappear. Their geometry does not.

Connection handout:

```console
$ ncat --ssl cyclotomic-echo-<id>.chals.z0d1ak.org 1337
```

## Executive Summary

The service asks for a short signature in the cyclotomic integer ring

```text
R = Z[x] / (x^128 + 1).
```

Its public key is a positive-definite Hermitian form `Q`. The verifier hashes a
fixed target message and a chosen salt to two binary ring elements `(x,y)`, then
accepts a short vector `(e0,e1)` in the parity class

```text
(e0,e1) = (x,y) mod 2R^2.
```

Only the compressed second component `s1 = (y-e1)/2` is submitted; the verifier
reconstructs the first component with a nearest-plane rounding step.

The second handout file, `recovery.json`, contains four polynomials named
`f,g,F,G`. They are not incidental recovery data. They form the exact private
NTRU basis

```text
    [ f  g ]
B = [      ]
    [ F  G ]
```

behind the live public form. Two checks prove this:

```text
fG - gF = 1
Q = B * B^*
```

where `B^*` is the conjugate transpose. The determinant is the unit `1`, so the
basis has an integral inverse:

```text
         [  G  -g ]
B^-1  = [        ].
         [ -F   f ]
```

That turns signing into coefficient-wise parity reduction. Map the hash point
through `B`, replace every coefficient by its residue in `{0,1}`, and map the
tiny result back through `B^-1`. The resulting vector has the required parity,
the required sign, and norm only `133` against the verifier's bound of `16384`.
Submitting its compressed `s1` returns the flag.

The supplied [`solve.py`](solve.py) performs the complete attack over TLS using
only Python's standard library. No Sage, lattice reducer, or numerical
approximation is required.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/crypto_cyclotomic-echo.tar.gz`](challenge/crypto_cyclotomic-echo.tar.gz) | Original handout | `22ebce0eb842b3a9d6011afc102164c7ebcd8d33cffe99f0b99641d9c6364261` |
| [`challenge/verifier.py`](challenge/verifier.py) | Original Sage verifier | `d960c6f0c718484deb4fbcf84ae49a8f842185dba859cbc1fe54037499345b59` |
| [`challenge/recovery.json`](challenge/recovery.json) | Supplied `(f,g,F,G)` recovery tuple | `a618416023d13a599760d705123447f1c3e3b3fa9cc4bb04b81a9f969932bc3e` |
| [`solve.py`](solve.py) | End-to-end standard-library TLS forgery | `9c0c2a91d8273f4e77a7603cd2e2618438cf4cfb813f1b47f91af44525c9b8ef` |
| [`verify_offline.py`](verify_offline.py) | Offline reproduction of the captured forgery | `eedaa6b1fde2efb618c9a491ca66a570c136d5e16e6c9a63d85e3455dbcb8d1a` |
| [`artifacts/instance.json`](artifacts/instance.json) | Exact public instance used for the solve | `0550837c0769d19162ba0027bbd6b26bc36d50988731159f5fba0f91e6a329f2` |
| [`artifacts/forgery.json`](artifacts/forgery.json) | Accepted salt and 128-coefficient `s1` | `e16ab679b393b981e971ad1ea16a4776882e7d6767b8576118e514d7b299b828` |
| [`artifacts/basis-analysis.txt`](artifacts/basis-analysis.txt) | Determinant, Gram, weight, sign, and norm checks | `8a459d4a4c703ecef6b08e8d8160cd95ea1c06cbbd41bd2abc8be8cf0c6b551b` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful live exploit transcript | `41712e46bb93cab78423371722f7f9d199abc67474e4ac8e5dadfe89452758fc` |

The service is an instancer, so its hostname expires. The captured instance,
forgery, and offline verifier preserve every value needed to audit the solve
after the live host disappears.

## 1. Handout Triage

The archive contains only two files:

```console
$ tar -tzvf crypto_cyclotomic-echo.tar.gz
... 1306 crypto_cyclotomic-echo/dist/recovery.json
... 7814 crypto_cyclotomic-echo/dist/verifier.py
```

`verifier.py` is an executable Sage script. Its important constants are:

```python
N = 128
CONDUCTOR = 2 * N
K = CyclotomicField(CONDUCTOR, "z")
SALT_BYTES = 16
VERIFY_BOUND = 2 * N * (2 * 4) ** 2  # 16384
```

The fixed target decodes to:

```text
Authorize release of the Cyclotomic Echo archive.
```

On connection, the service sends one canonical JSON public instance containing:

- `q00_half`: 64 coefficients encoding one self-adjoint ring element;
- `q10`: 128 coefficients encoding the off-diagonal form entry;
- a SHA-256-bound `instance_id` and `assignment_id`;
- the target message, salt length, and norm bound.

It then reads one JSON object with exactly two fields:

```json
{
  "salt_hex": "<16 bytes, lowercase hex>",
  "s1": ["128 signed integer coefficients"]
}
```

There is no signing oracle and no opportunity to collect samples. The forgery
must be derived entirely from the public instance and the recovery tuple.

## 2. The Cyclotomic Ring

For conductor `256`, the 256th cyclotomic polynomial is

```text
Phi_256(x) = x^128 + 1.
```

Every ring element is represented by 128 integer coefficients. Multiplication
is ordinary polynomial convolution followed by the negacyclic reduction

```text
x^128 = -1.
```

So a term `c*x^(128+i)` folds into `-c*x^i`.

Cyclotomic conjugation sends `x` to `x^-1`. In the coefficient basis used by
the challenge,

```text
bar([a0,a1,...,a127]) = [a0,-a127,-a126,...,-a1].
```

These two operations are all the solver needs. The code implements them with
plain integer lists; Sage is necessary only for the original verifier's exact
field division and rounding.

## 3. Understanding the Public Form

The verifier expands `q00_half` into a 128-coefficient self-adjoint element
`a`, reads `b = q10`, and derives `c` as

```text
c = (1 + b*bar(b)) / a.
```

The complete Hermitian form is

```text
    [ a      bar(b) ]
Q = [               ].
    [ b         c   ]
```

The formula for `c` forces `det(Q)=1`:

```text
a*c - b*bar(b) = 1.
```

For a row vector `e=(e0,e1)`, the verifier measures

```text
norm_Q(e) = constant_coefficient(e * Q * e^*).
```

The last extraction is important. An element `p` satisfies

```text
constant_coefficient(p*bar(p)) = sum_i p[i]^2,
```

so this Hermitian norm becomes an ordinary squared coefficient norm after the
correct change of basis.

## 4. Hashing into a Parity Coset

For a 16-byte salt `t`, the verifier hashes the domain, instance ID, fixed
target, and salt with SHAKE-256:

```python
d = shake_256(
    b"cyclotomic-echo/sign/v2"
    + bytes.fromhex(instance_id)
    + len(target).to_bytes(4, "little")
    + target
    + t
).digest(32)
```

The 256 output bits are read least-significant-bit first and split into two
binary polynomials `(x,y)` of 128 coefficients each.

Given submitted `u=s1`, the verifier reconstructs the omitted coordinate:

```text
v  = round_coefficients(x/2 + (y/2-u)*b/a)
e0 = x - 2v
e1 = y - 2u.
```

Therefore

```text
e0 = x (mod 2)
e1 = y (mod 2).
```

The cryptographic task is to find a very short vector in this prescribed parity
coset. The verifier additionally requires the first nonzero coefficient of
`e1` to be positive and checks `norm_Q(e) <= 16384`.

## 5. Identifying the Recovered Private Basis

The file `recovery.json` stores four 128-coefficient polynomials:

```text
f, g       small coefficients, mostly in roughly [-6,6]
F, G       larger completion vectors, roughly in [-17,21]
```

The names strongly resemble an NTRU trapdoor. Define

```text
    [ f  g ]
B = [      ].
    [ F  G ]
```

and calculate its ring determinant. The result is exact:

```text
fG - gF = [1,0,0,...,0].
```

This is not a merely short basis; it is **unimodular over the ring**. Its inverse
has integral coefficients:

```text
         [  G  -g ]
B^-1  = [        ].
         [ -F   f ]
```

Next compute its Gram matrix:

```text
B*B^* =

[ f*bar(f)+g*bar(g)       f*bar(F)+g*bar(G) ]
[ F*bar(f)+G*bar(g)       F*bar(F)+G*bar(G) ].
```

The top-left entry reproduces all 128 coefficients of public `a`; the
bottom-left entry reproduces all 128 coefficients of public `b`. Since both
Gram matrices have determinant one, the bottom-right entry must also equal the
verifier's derived `c`. Thus

```text
Q = B*B^*.
```

This is the decisive observation behind the title: the signing key may have
"disappeared" from the service, but `recovery.json` preserves the exact geometry
of its private basis.

## 6. Forging by Modulo-2 Basis Reduction

Choose the deterministic salt

```text
t = 00000000000000000000000000000000.
```

For the captured instance, hashing gives binary polynomials with weights

```text
wt(x) = 69
wt(y) = 61.
```

Let `h=(x,y)`. Map this parity target through the private basis:

```text
w = hB

w0 = x*f + y*F
w1 = x*g + y*G.
```

Now reduce every coefficient modulo two to its representative in `{0,1}`:

```text
z0 = w0 mod 2
z1 = w1 mod 2.
```

For this instance,

```text
wt(z0) = 71
wt(z1) = 62.
```

Because `z = hB (mod 2)` and `B^-1` is integral, mapping back gives

```text
e = z*B^-1 = h (mod 2).
```

Expanding the inverse yields the two signature components directly:

```text
e0 =  z0*G - z1*F
e1 = -z0*g + z1*f.
```

If the first nonzero coefficient of `e1` is negative, negate both components.
Negation preserves parity modulo two and leaves the norm unchanged. In the
captured forgery the oriented first nonzero coefficient is `29`, so the sign
condition is satisfied.

Finally compress the signature to the only component accepted by the protocol:

```text
s1 = u = (y-e1)/2.
```

Every division is exact because `e1=y (mod 2)`. The largest submitted
coefficient has absolute value only `24`, far inside the verifier's 31-bit
format limit.

The verifier uses `u` to recover `v=(x-e0)/2` through its public rounding
formula. The secret-basis construction puts the candidate in the corresponding
rounding cell; the supplied Sage verifier and live service both accept the
result.

## 7. Why the Forgery Is So Short

The Gram identity eliminates any need to evaluate the public quadratic form
directly:

```text
norm_Q(e)
  = constant_coefficient(e * B * B^* * e^*)
  = coefficient_norm(eB)^2
  = coefficient_norm(z)^2.
```

Before the optional global negation, every coefficient of `z0,z1` is zero or
one. Consequently its squared norm is simply its Hamming weight:

```text
norm_Q(e) = wt(z0) + wt(z1)
          = 71 + 62
          = 133.
```

The acceptance margin is enormous:

```text
133 <= 16384.
```

This also explains why no LLL/BKZ attack is needed. The handout already gives a
unimodular private basis; modulo-two reduction in that basis constructs a tiny
coset representative immediately.

## 8. Remote Exploit

Run the solver against a fresh instance from this directory:

```console
$ python3 solve.py cyclotomic-echo-<id>.chals.z0d1ak.org 1337
[*] instance: f6071198e87eb6e1aba739acb5748e2a5dcd21277cd8f543bae7508a36ac3bc8
[+] recovery basis matches the public Gram matrix
[+] forged norm: 133 <= 16384
[+] max |s1[i]|: 24
[+] response: {"flag":"zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}","ok":true}
[+] flag: zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}
```

The solver deliberately validates the recovery data before transmitting
anything:

1. Check `fG-gF=1` exactly in `R`.
2. Reconstruct all coefficients of public `q00` and `q10` from the basis.
3. Hash the target and salt exactly as the verifier does.
4. Build `z`, apply `B^-1`, and check both parity equations.
5. Recompute `eB` and its coefficient norm.
6. Refuse to submit if the norm exceeds the public bound.
7. Send canonical compact JSON over a certificate-verified TLS connection.

## 9. Offline Reproduction

The captured instance and forgery can be checked without Sage and without the
expired host:

```console
$ python3 verify_offline.py
[+] fG - gF = 1 in Z[x]/(x^128 + 1)
[+] q00: all 128 reconstructed coefficients match
[+] q10: all 128 reconstructed coefficients match
[+] hash weights: wt(x)=69, wt(y)=61
[+] reduced weights: wt(z0)=71, wt(z1)=62
[+] reduced norm: 133
[+] oriented e1 first nonzero: 29
[+] max |s1[i]|: 24
[+] captured forgery reproduced exactly: True
[+] norm check: 133 <= 16384
```

`verify_offline.py` regenerates the complete JSON forgery and asserts that it
matches [`artifacts/forgery.json`](artifacts/forgery.json) coefficient for
coefficient.

## Flag

```text
zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}
```

## Lessons

- **A Gram matrix hides orientation, not geometry.** Knowing a short basis `B`
  with `Q=B*B^*` converts the public norm back into ordinary coefficient norm.
- **Check the determinant first.** `fG-gF=1` immediately reveals that the
  recovery tuple is an integral change of basis, making `B^-1` exact and cheap.
- **Parity cosets are easy in a unimodular basis.** Map through `B`, reduce each
  coefficient modulo two, and map back. No general closest-vector algorithm is
  needed.
- **Compressed signatures can still be constructed in full.** Build `(e0,e1)`
  with the trapdoor, orient it, then publish only `s1=(y-e1)/2` as the protocol
  expects.
- **Validate leaked key material against the live public key.** Matching every
  `q00` and `q10` coefficient prevents submitting a forgery made from an
  unrelated or decoy recovery tuple.
