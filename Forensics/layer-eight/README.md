# layer-eight

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Forensics |
| Author | Abhi404 |
| Points | 120 |
| Solves at time of solving | 141 |
| Flag | `zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}` |

> can someone please tell me what happened to the oceanographic beacon? it was
> transmitting fine and then it just stopped. the last transmission was a bit
> garbled, but i think it might have been trying to tell us something

## Executive Summary

The "garbled last transmission" is `app-image.tar`, an **OCI/Docker container
image** (`nimbusnotes:1.4.2`). The challenge name is the whole hint: **layer 8**
is the image layer that *deletes* the build secrets. But deleting a file in a
container layer does not remove its bytes — it only writes a **whiteout marker**
(`.wh.<name>`) in the newer layer, while the file's real content lives on
forever in the earlier layer that added it.

Three files are "removed" in layer 8: a build `deploy_key`, a `postinstall.sh`,
and a `provenance.py`. We carve the first two back out of layers 4 and 6, then
follow the recovered `provenance.py` to reverse a small key-management scheme:

- An **AES-256-GCM envelope** (`version ‖ nonce ‖ ciphertext ‖ tag`) was
  base64-encoded and **sharded across three image labels**
  (`com.nimbusnotes.provenance.part-{a,b,c}`), to be reassembled in the order
  named by a fourth label, `layout = c,a,b`.
- The GCM **key is derived from the carved `deploy_key`** and the build-step
  digest: `key = sha256(deploy_key_bytes ‖ step_digest)`.

Reassembling the shards, deriving the key from the recovered secret, and
decrypting (the GCM tag verifies) yields the flag:

```
zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}
```

The flag states the lesson outright: **whiteout layers still remember secrets.**

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end solver: parse the OCI image → carve deleted files → reassemble the envelope → decrypt → flag |
| [`aesgcm.py`](aesgcm.py) | Dependency-free pure-python AES-256 + GCM (decrypt/verify), validated against NIST vectors |
| [`artifacts/layer-map.txt`](artifacts/layer-map.txt) | Every layer mapped to its build step, files added, and whiteouts |
| [`artifacts/image-config.json`](artifacts/image-config.json) | The image config blob (history + provenance labels) |
| [`artifacts/provenance.py`](artifacts/provenance.py) | The **carved** reassembly/decryption script (deleted in layer 8) |
| [`artifacts/deploy_key`](artifacts/deploy_key) | The **carved** build secret (deleted in layer 8), the GCM key material |
| [`artifacts/postinstall.sh`](artifacts/postinstall.sh) | The carved build hook that ran `provenance.py` |
| [`artifacts/envelope-decode.txt`](artifacts/envelope-decode.txt) | Full worked reconstruction: shards → envelope → key → plaintext |
| [`challenge/forensics_layer_eight.zip`](challenge/) | Original handout (contains `app-image.tar`) |

Everything runs on the Python standard library alone — `aesgcm.py` is a
self-contained AES-256-GCM so the solve works even where `pip install
pycryptodome` is unavailable.

## 1. Identifying the "Transmission"

`app-image.tar` is not telemetry; it is an **OCI image layout**:

```console
$ tar tf app-image.tar
blobs/sha256/03d3e9ab...   ... (11 blobs)
index.json
manifest.json
oci-layout                 # {"imageLayoutVersion":"1.0.0"}
```

`index.json` names the image `nimbusnotes:1.4.2` and points at a manifest; the
manifest lists a **config blob** and **nine gzip'd rootfs layers**. Nine layers,
and the challenge is called *layer-eight* — that is where to look.

## 2. Reading the Build History

The config blob records the Dockerfile-equivalent build history. Two lines are
the whole story:

```
LAYER 4  install -m600 /run/secrets/deploy_key /app/.secrets/deploy_key
LAYER 8  rm -f /app/.secrets/deploy_key /app/scripts/postinstall.sh /usr/lib/nimbus/provenance.py
```

A secret is mounted into the image in an early layer and *deleted* in a later
one. It also exposes a provenance scheme in the image `Labels`:

```
com.nimbusnotes.provenance.layout = c,a,b
com.nimbusnotes.provenance.part-a = dZ4Ranut8tzxp+B9+sZ7H+8XGSdtBFAK
com.nimbusnotes.provenance.part-b = XcH39DQsNt67UAbE90W4KrXkQc0DyVT8
com.nimbusnotes.provenance.part-c = AU5pbWJ1c05vdGVzIUHvlVyex5o1USWI
com.nimbusnotes.provenance.step   = sha256:25df7c6f...642383d8
```

## 3. Why "Deleted" Isn't Deleted — the Layer 8 Whiteouts

Container layers are stacked diffs. Removing a file does not rewrite the layer
that contains it; the overlay filesystem instead records a **whiteout** — a
zero-byte marker named `.wh.<file>` — in the *newer* layer. The bytes remain in
the older layer. Unpacking layer 8 shows exactly that (see
[`artifacts/layer-map.txt`](artifacts/layer-map.txt)):

```
LAYER 8  (rm -f ...)
  x app/.secrets/deploy_key        -> app/.secrets/.wh.deploy_key
  x app/scripts/postinstall.sh     -> app/scripts/.wh.postinstall.sh
  x usr/lib/nimbus/provenance.py   -> usr/lib/nimbus/.wh.provenance.py
```

So layer 8 only *marks* the files gone. We recover the content by extracting the
earlier layers that added them:

- **`deploy_key`** was added in **layer 4** → carve it there.
- **`provenance.py`** and **`postinstall.sh`** were added in **layer 6** → carve
  them there.

## 4. The Recovered Scheme

The carved [`provenance.py`](artifacts/provenance.py) spells out the key
management:

```python
key_bytes = open('/app/.secrets/deploy_key','rb').read()
step = os.environ['NIMBUS_STEP_DIGEST']
k = hashlib.sha256(key_bytes + bytes.fromhex(step.split(':',1)[1])).digest()
aad = ('nimbusnotes:1.4.2|' + step).encode()
# envelope v1: version || nonce[12] || ciphertext || tag[16]
# the registry adapter shards base64(envelope) across provenance labels
```

Everything it needs is now recoverable:

- **`key_bytes`** — the full 139-byte `deploy_key` file we carved from layer 4
  (the whole PEM, headers and trailing newline included: `open(...).read()`).
- **`step`** — the `NIMBUS_STEP_DIGEST`, published in the clear as the
  `com.nimbusnotes.provenance.step` label
  (`sha256:25df7c6f...` — not coincidentally, the **diff_id of layer 6**).
- **the envelope** — `base64(envelope)` split across the three `part-*` labels.

## 5. Reassembling and Decrypting the Envelope

The `layout = c,a,b` label is the shard order. Each `part-*` is 32 base64 chars
(24 bytes), and concatenating them in order `c, a, b` and base64-decoding gives a
72-byte envelope:

```
version(1) ‖ nonce(12) ‖ ciphertext(43) ‖ tag(16)
  version    = 0x01
  nonce      = 4e696d6275734e6f74657321   ("NimbusNotes!")
  ciphertext = 41ef955c...36de            (43 bytes = plaintext length)
  tag        = bb5006c4f745b82ab5e441cd03c954fc
```

Deriving the key and AAD exactly as the script does and running AES-256-GCM:

```
key = sha256(deploy_key_bytes ‖ 25df7c6f...383d8)
    = 694ee5b6...25c157af
aad = nimbusnotes:1.4.2|sha256:25df7c6f...642383d8
```

The **GCM tag verifies** — which authenticates that every recovered input
(secret, step digest, AAD, shard order) is correct — and the plaintext is the
flag (full trace in [`artifacts/envelope-decode.txt`](artifacts/envelope-decode.txt)):

```
zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}
```

## 6. Reproducing

```console
$ python3 solve.py challenge/app-image.tar
[*] image: nimbusnotes:1.4.2
[*] layer 8 whiteouts (deleted files): ['app/.secrets/deploy_key', 'app/scripts/postinstall.sh', 'usr/lib/nimbus/provenance.py']
[*] recovered deploy_key (139 bytes) from layer 4
[*] recovered provenance.py from layer 6
[*] layout=['c', 'a', 'b'] step=sha256:25df7c6f...642383d8
[*] envelope: version=1 nonce=b'NimbusNotes!' ct=43B tag=bb5006c4f745b82ab5e441cd03c954fc
[*] GCM tag verified: True
[+] FLAG: zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}
```

No third-party packages required; the bundled `aesgcm.py` is checked against the
NIST GCM AES-256 known-answer vectors (Test Cases 13 and 14) before use.

## Root Cause and Fix

- **Root cause:** secrets were "removed" in a later image layer instead of never
  being committed. A layer `rm` leaves a whiteout; the secret's bytes persist in
  the layer that added them and ship inside the final image. Publishing the
  step digest and the encrypted-envelope shards as labels then made the rest of
  the key-management scheme fully recoverable from the same image.
- **Fix:** never let a secret enter a layer at all. Use `RUN --mount=type=secret`
  *without* copying the secret onto disk, multi-stage builds that leave secrets
  in a discarded stage, or build-time secret managers. Squashing/flattening or
  `--squash` only helps if the secret never appears in the final flattened
  filesystem. Rotate any credential that has ever touched a layer.

## Lessons

- **Whiteouts are not shredders.** `docker history`, a raw `tar`, or `dive`
  expose every "deleted" file; layer removal is metadata, not erasure.
- **Treat the image config as evidence.** History lines and labels reconstruct
  the build, name the secret, and here handed over the entire decryption recipe.
- **A verifying GCM tag is proof you got everything right.** When the tag checks
  out, the carved secret, the step digest, the AAD string and the shard order
  are all confirmed at once — no guessing whether the plaintext is "the flag".
