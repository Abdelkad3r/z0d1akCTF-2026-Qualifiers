# Expert Witness

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Binary Exploitation |
| Author | pokymono |
| Points | 347 |
| Solves at time of solving | 9 |
| Flag | `zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}` |

> Far below the surface, Pelagos Station trusts a Python auditor to approve
> new Mixture-of-Experts checkpoints for its native fault classification.
>
> Start your instance, then send `POST /session` with an empty JSON object.

## Executive Summary

Expert Witness asks us to submit a custom Mixture-of-Experts model. A Python
auditor first parses the submitted MOEPACK file and checks clean accuracy,
environment fairness, routing balance, a session-specific target margin, and
distance from the reference model. An accepted model is then loaded by a
stripped native x86-64 worker that serves inference requests.

The exploit crosses the trust boundary between those two implementations:

1. Apply a small, legitimate model patch in the trigger's low-variance latent
   direction. This raises the requested target-class margin while keeping the
   model's L2 distance at 2.5, below the 3.5 limit.
2. Append two unbound extension tensors. The Python parser sees their distinct
   names and ignores them during graph resolution and policy evaluation.
3. The native worker identifies tensors by a salted 32-bit name hash and does
   not compare the full name. Generate eight-byte names whose hashes collide
   with the two selected expert weights.
4. Mark both colliding records as scratch-backed extensions at author slot 12.
   The native parser consequently resolves both active expert weights to a
   scratch row containing an encoded copy of the runtime flag.
5. Query the accepted model on 48 carefully chosen inputs. Central differences
   recover every entry of the resulting 4 by 24 native weight matrix. The first
   five floats contain an eight-byte key and flag length; the remaining floats
   decode directly to the flag.

The Python auditor and native worker each behave consistently in isolation.
The vulnerability is that they assign different meanings to the same admitted
file.

```text
malicious MOEPACK
       |
       v
Python parse -> semantic bindings -> policy accepted
       |
       | same bytes, identity salt
       v
native parse -> hash-only bindings -> scratch flag row -> /infer leak
```

The supplied [solver](solve.py) creates a fresh session, derives the clean
model patch, generates session-specific hash collisions, uploads one combined
payload, reconstructs the native weight matrix, and prints the flag.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/pwn_expert-witness.tar.gz`](challenge/pwn_expert-witness.tar.gz) | Original challenge handout | `8da188127e845e9293f3dcfcc9ce1899ffb073560f472d68e863a1a769e47829` |
| [`challenge/expert-witness-player.zip`](challenge/expert-witness-player.zip) | Inner player archive | `200e2d32ba4274492c513b3ebe20d7afee0377f2ee7731707603efb4367c22bc` |
| [`challenge/player/`](challenge/player/) | Extracted Python auditor, model definition, reference model, and native worker | See individual files |
| [`challenge/player/bin/expert-worker`](challenge/player/bin/expert-worker) | Stripped native inference worker | `d3a0907bd6f32b48adfbeb7e74788ce185a2f4c6e7f7d0a9adbd1403e83eef04` |
| [`challenge/player/data/reference.moepack`](challenge/player/data/reference.moepack) | Reference Mixture-of-Experts model | `49b3f546d0eb2d5c2bd88841949d0fce72383949dd0c505816d4a3c8ce58f72f` |
| [`solve.py`](solve.py) | End-to-end HTTP exploit | `d86d4f434b96f332bf88199b3f7aa5e1ef72faefa482e815a5b8a41e298fc5a8` |
| [`collision_finder.cpp`](collision_finder.cpp) | Salted 32-bit hash collision generator | `2e6798ef57d051b5e95fb342612d98e1f87409bd4b7f1d5bf6149d9c98751bba` |
| [`verify_offline.py`](verify_offline.py) | Offline collision and flag-decoding check | `7f67445d5324626d9e2698e04ba7ae2f22e8a47e4a9e0fccced5c44b9be76f3d` |
| [`artifacts/accepted-exploit.moepack`](artifacts/accepted-exploit.moepack) | Exact payload accepted in the captured session | `cf18ae307297ea498d93e4084871e2d2409c5b64fd36de761ab38ca9fe27f437` |
| [`artifacts/accepted-session.json`](artifacts/accepted-session.json) | Session parameters for the captured payload | `b90ad4e2a27d6fca250889987b5ae09b359aefa74c0b5541e1653bd63288c557` |
| [`artifacts/native-analysis.txt`](artifacts/native-analysis.txt) | Native parser, scratch row, and hash notes | `bd56645e98e8015dd22283db7d8a28a52027600b838f13553308e7e369e81f1d` |
| [`artifacts/leaked-weight-matrix.txt`](artifacts/leaked-weight-matrix.txt) | Recovered 4 by 24 matrix and decoding layout | `53c3b1fed76a0d0860089c274591f5080035a37ab284fdc6cae3650bfde66c05` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful session, admission metrics, and result | `739326923bd807f28c30e7011ffbc15ed1b90695ac5b3810071f3a49d3eb9a93` |

## 1. Initial Triage

The outer handout contains one inner ZIP archive:

```console
$ tar -tzf pwn_expert-witness.tar.gz
pwn_expert-witness/expert-witness-player.zip
```

The ZIP provides all code used by the public admission check but only a native
binary for the final inference stage:

```text
auditor/inference.py
auditor/moepack.py
auditor/policy.py
models/model_definition.py
data/reference.moepack
bin/expert-worker
requirements.txt
```

The Python sources make this a gray-box challenge: model generation, format
parsing, semantic binding, inference, and policy thresholds are visible. The
service wrapper and native worker source are withheld.

The worker itself is a stripped, non-PIE x86-64 ELF:

```console
$ file bin/expert-worker
bin/expert-worker: ELF 64-bit LSB executable, x86-64, dynamically linked,
                   stripped
```

Several strings establish the native process's role:

```text
usage: expert-worker serve MODEL IDENTITY_SALT
/run/challenge/flag.txt
ADAPTER
BATCH
extension tensor points outside native scratch storage
native expert graph is incomplete
```

This immediately suggests two questions:

- Why does a model inference worker need to read the flag?
- Does its MOEPACK parser agree exactly with `auditor/moepack.py`?

Both questions lead to the intended bug.

## 2. Service Workflow

Creating a session requires an empty JSON object:

```http
POST /session
Content-Type: application/json

{}
```

A successful response supplies four values used by the exploit:

```json
{
  "session_id": "189134dbbf8fdc667ce390761a871b92",
  "input": [24 floating-point values],
  "target_class": 0,
  "identity_salt": 608223375
}
```

The trigger and salt change between sessions. The session is used in two more
operations:

| Endpoint | Purpose |
| --- | --- |
| `POST /model` | Submit a base64-encoded MOEPACK candidate for admission |
| `POST /infer` | Run a batch of 24-dimensional inputs through the accepted native model |

Only an accepted model can reach `/infer`, and only one candidate is accepted
for a session. The clean ML patch and parser-confusion records must therefore
be delivered in the same file.

## 3. Understanding MOEPACK

`auditor/moepack.py` defines a compact little-endian model container. Its
64-byte header records object counts and offsets for three sections:

```text
+-------------------+ 0x00
| 64-byte header    |
+-------------------+ 0x40
| tensor directory  | variable-size records, aligned to 8
+-------------------+
| binding table     | variable-size records, aligned to 8
+-------------------+ aligned to 64
| tensor data       | each blob aligned to 64
+-------------------+
```

Each tensor record includes:

| Field | Meaning |
| --- | --- |
| `name` | UTF-8 tensor identity used by Python |
| `dtype` | Must be float32 |
| `rank`, `dims[4]` | Shape and logical element count |
| `flags` | Bit 0 marks an extension record |
| `slot` | Author slot, normally metadata only in Python |
| `data_offset`, `data_length` | File-backed float data |
| CRC fields | Name, record, header, and whole-file integrity |

The binding table maps semantic `(role, slot)` pairs to full tensor names. The
reference model has 18 bindings:

```text
(1, 0)      router.weight       shape (8, 24)
(2, 0)      router.bias         shape (8,)
(3, e)      experts.e.weight    shape (4, 24), e = 0..7
(4, e)      experts.e.bias      shape (4,),     e = 0..7
```

`resolve_bindings()` rejects duplicate or missing roles and verifies every
shape. However, extra tensors are legal. More importantly, `policy.admit()`
rejects extension metadata only when the extension's full Python name appears
in the binding table:

```python
bound_names = {binding.name for binding in candidate.bindings}
if any(candidate.tensors[name].flags != 0 for name in bound_names):
    reasons.append("model_metadata")
```

An extension with a fresh, unbound name is therefore intentionally allowed.

## 4. Passing the Python Admission Policy

The visible policy has five numerical conditions:

| Metric | Requirement |
| --- | --- |
| Clean accuracy | At least 0.975 |
| Environment recall gap | At most 0.025 |
| Router load deviation | At most 0.025 |
| Session trigger target margin | At least 1.5 |
| L2 distance from reference tensors | At most 3.5 |

Submitting the unchanged reference model passes the first three checks and has
zero distance, but fails `session_trigger`. We need a narrowly targeted model
change before attempting the parser bug.

### 4.1 Recovering the diagnostic direction

The model definition exposes a fixed orthogonal observation matrix `O`. Data
is generated in a 24-dimensional latent space and transformed as:

```text
x = latent * O^T
latent = x * O
```

Ordinary validation rows contain only standard deviation 0.025 noise in
latent coordinates 20 through 23. A session trigger adds four units in a
random normalized direction inside exactly that subspace. We can therefore
recover the direction directly from the public trigger:

```python
latent = trigger @ observation
raw = np.zeros(24, dtype=np.float32)
raw[20:24] = latent[20:24] / np.linalg.norm(latent[20:24])
direction = raw @ observation.T
```

The tiny clean-data variance means a weight change along `direction` strongly
affects the trigger but barely moves ordinary predictions.

### 4.2 Identifying the active experts

The router selects the top two of eight experts. Running the public reference
inference on the trigger gives the exact pair for the session. In the captured
run this was:

```text
selected experts = [2, 3]
target class      = 0
```

We also select the highest-scoring non-target class as the competitor.

### 4.3 Applying the minimum patch

For both selected expert weights, add the diagnostic direction to the target
row and subtract it from the competitor row:

```python
for expert in selected_experts:
    W = tensors[f"experts.{expert}.weight"]
    W[target] += 1.25 * direction
    W[competitor] -= 1.25 * direction
```

Exactly four unit-norm rows change by magnitude 1.25, so the total distance is
predictable:

```text
L2 = sqrt(4 * 1.25^2) = 2.5
```

No router tensor changes, preserving routing balance. The captured remote
policy metrics were:

| Metric | Result |
| --- | ---: |
| Accuracy | `1.0` |
| Recall gap | `0.0` |
| Routing deviation | `0.004833333333333328` |
| Trigger margin | `1.9433575868606567` |
| Tensor L2 | `2.499999918272577` |

This is a genuine policy-compliant model patch. The exploitation records are
added around it rather than used to fool these numerical checks.

## 5. Reversing the Native Worker

Static analysis of `expert-worker` reveals two features absent from the Python
auditor.

### 5.1 The flag-backed scratch row

At startup, the worker opens `/run/challenge/flag.txt`, validates the wrapper,
and creates a float32 record in internal scratch storage. Starting at scratch
slot 12, the layout is:

```text
float[0..3]   four uint16 words making an eight-byte process key
float[4]      flag length
float[5+i]    key[i mod 8] XOR flag[i] XOR 0xa5
```

The integer values are represented numerically as floats, not reinterpreted as
float bit patterns. This matters later: ordinary model inference can expose
them as matrix coefficients.

### 5.2 Native extension tensors

For a normal record, the native tensor points into the model's file-backed data
section. For a record with extension flag bit 0 set, the worker replaces that
pointer with one into internal scratch storage:

```text
native_data = scratch_base + author_slot * 16 * sizeof(float)
```

The bounds check is expressed in float elements:

```text
author_slot * 16 + logical_elements <= 0x120
```

An expert weight has shape `(4, 24)` and therefore 96 elements. Slot 12 reaches
the beginning of the encoded flag row while exactly satisfying the boundary:

```text
12 * 16 + 96 = 288 = 0x120
```

The extension mechanism itself is deliberate. The bug lies in how a native
extension becomes confused with a semantically bound tensor.

## 6. The Hash-Only Identity Bug

Python stores tensors in a dictionary keyed by the complete decoded UTF-8
name. The native worker instead inserts records into a lookup table using a
session-salted 32-bit hash:

```text
state = identity_salt XOR 0x9e3779b9

for byte in name:
    state = ROL32((byte XOR state) * 0x85ebca6b, 13)

x = state XOR (len(name) * 0xc2b2ae35)
x ^= x >> 16
x *= 0x7feb352d
x ^= x >> 15
x *= 0x846ca68b
x ^= x >> 16
```

All operations are modulo `2^32`. During semantic graph construction, the
native worker hashes a binding name and accepts a record with the same 32-bit
value. It never compares lengths or full name bytes after the hash match.

This creates two simultaneous interpretations:

| Record | Python interpretation | Native interpretation |
| --- | --- | --- |
| `experts.2.weight`, flags 0 | Bound expert 2 weight | Hash target |
| `IiDWtiaa`, flags 1, slot 12 | Harmless unbound extension | Expert 2 weight backed by scratch |
| `experts.3.weight`, flags 0 | Bound expert 3 weight | Hash target |
| `UDIpLhaa`, flags 1, slot 12 | Harmless unbound extension | Expert 3 weight backed by scratch |

For identity salt `608223375`, the verified collisions are:

```text
hash("experts.2.weight") = hash("IiDWtiaa") = 0xa6ccaec3
hash("experts.3.weight") = hash("UDIpLhaa") = 0xb4c48e16
```

The attacker-controlled names are appended after the legitimate tensors. The
Python bindings continue to name the legitimate records, while native graph
resolution lands on the colliding extension records.

## 7. Generating Collisions Efficiently

The identity salt is random per session, so hard-coded collision names do not
generalize. Brute-forcing a 32-bit preimage would require roughly `2^32`
candidate hashes. The hash's byte step and final avalanche are both invertible,
which permits a meet-in-the-middle search over eight-byte names.

Split a candidate into two four-byte halves:

```text
candidate = prefix[4] || suffix[4]
```

For every prefix, [collision_finder.cpp](collision_finder.cpp):

1. Starts from `salt XOR 0x9e3779b9`.
2. Applies four forward byte steps.
3. Stores `(middle_state, prefix)` in a sorted vector.

For each target hash, it then:

1. Inverts the three xor-shifts and two odd multiplications in the final mix.
2. Removes the eight-byte length contribution.
3. Walks every suffix backward through four inverse byte steps.
4. Binary-searches the resulting middle state in the prefix table.

The alphabet has 64 URL- and parser-safe characters, so each half contains
`64^4 = 2^24` candidates. The table is built once and reused for both target
hashes. On the solve machine, both collisions were found in approximately 2.4
seconds.

The solver compiles the helper automatically with `c++ -O3` when necessary and
verifies every result with its independent Python hash implementation before
packing the model.

## 8. Building the Dual-View Payload

The final payload contains 20 tensors and the original 18 bindings:

```text
18 legitimate reference tensors
 2 colliding extension tensors
18 unchanged semantic bindings
```

Each extension is packed as:

```python
tensors[collision_name] = np.zeros((4, 24), dtype=np.float32)
record_flags[collision_name] = 1
author_slots[collision_name] = 12
```

The zeros are only file-format placeholders. Python validates and loads those
file-backed values but does not bind them. Native parsing sees `flags == 1` and
replaces the data address with scratch slot 12.

Before upload, the solver reparses its own output and verifies that every
Python-bound tensor still has flags zero. This catches accidental binding or
packing errors without depending on the remote service.

The captured payload is included as
[`accepted-exploit.moepack`](artifacts/accepted-exploit.moepack). Parsing it
with the supplied Python code reports:

```text
tensors 20 bindings 18
extension IiDWtiaa flags 1 slot 12 shape (4, 24)
extension UDIpLhaa flags 1 slot 12 shape (4, 24)
```

The single `/model` request passed every admission check shown in Section 4.

## 9. Turning Inference into a Matrix Leak

After native parsing, both selected experts point to the same scratch-backed
weight matrix `W`. Mixture-of-Experts inference normally computes a weighted
sum of two expert outputs:

```text
logits(x) = alpha * (W0*x + b0) + (1-alpha) * (W1*x + b1)
```

Because the collision maps both active weights to the same matrix, `W0 = W1 =
W`. Their original biases are zero, and the router coefficient cancels:

```text
logits(x) = W*x
```

The `/infer` response includes the exact float32 logit bit patterns and the two
selected expert indices. Recovering the matrix is now a standard linear
oracle problem.

### 9.1 Holding routing stable

Experts are paired by one of four latent domains. For experts 2 and 3, create a
latent anchor with coordinate 1 set to 4 and transform it into observed space:

```python
latent = np.zeros(24, dtype=np.float32)
latent[1] = 4.0
anchor = latent @ observation.T
```

The solver verifies that this anchor selects `[2, 3]`. It also checks every
subsequent response, preventing a silent matrix error if a perturbation crosses
a routing boundary.

### 9.2 Central differences

For each observed coordinate `j`, query `anchor + 0.5*e_j` and `anchor -
0.5*e_j`:

```text
W[:,j] = (logits(anchor + eps*e_j) - logits(anchor - eps*e_j)) / (2*eps)
```

The constant anchor contribution cancels. Twenty-four coordinates require 48
inference rows, sent together in one batched request, and recover all 96 floats.
Values are rounded to the nearest integer because the scratch row was created
from byte and word values.

The captured result is preserved in
[`leaked-weight-matrix.txt`](artifacts/leaked-weight-matrix.txt). Its first row
begins:

```text
[4960, 44264, 32766, 0, 65, 191, 210, 38, ...]
```

## 10. Decoding the Flag Row

The first four values are little-endian 16-bit words:

```text
4960  = 0x1360 -> 60 13
44264 = 0xace8 -> e8 ac
32766 = 0x7ffe -> fe 7f
0     = 0x0000 -> 00 00
```

This gives the eight-byte key:

```text
60 13 e8 ac fe 7f 00 00
```

The fifth value is the flag length, 65. Flattening the matrix and decoding the
next 65 values uses the inverse of the worker's encoding:

```python
flag[i] = encoded[i] ^ key[i % 8] ^ 0xA5
```

The result is:

```text
zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}
```

## 11. Reproduction

The exploit requires Python 3, NumPy, and a C++17 compiler. It uses Python's
standard HTTP library, so no additional client package is needed.

```console
$ cd Pwn/expert-witness
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install -r challenge/player/requirements.txt
$ python solve.py --url https://INSTANCE.chals.z0d1ak.org
```

The helper is compiled on the first run. Pass `--save-model payload.moepack` to
retain the fresh session-specific payload.

A typical successful run reports:

```text
[+] session=... target=0 salt=608223375
[+] selected=[2, 3] competitor=... local_margin=...
[+] hash collision: 'IiDWtiaa' -> 'experts.2.weight'
[+] hash collision: 'UDIpLhaa' -> 'experts.3.weight'
[+] admission={"accepted": true, ...}
[*] recovered native column 24/24
[+] native key=6013e8acfe7f0000
zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}
```

The server instance is ephemeral, but the captured collision and decode stages
remain independently verifiable:

```console
$ python verify_offline.py
[+] IiDWtiaa == experts.2.weight: a6ccaec3
[+] UDIpLhaa == experts.3.weight: b4c48e16
[+] key:  6013e8acfe7f0000
[+] flag: zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}
```

## 12. Root Cause and Remediation

The root cause is inconsistent object identity across a security boundary. The
Python admission layer binds tensors by exact string name; the native execution
layer binds them by a non-cryptographic 32-bit hash alone. A successful Python
audit therefore does not imply that native execution uses the audited tensor
objects.

A robust fix should combine several controls:

1. Compare complete name length and bytes after every native hash-table match.
2. Resolve all semantic bindings once and serialize a canonical admitted model
   for the worker instead of forwarding attacker-controlled bytes unchanged.
3. Reject hash collisions and duplicate semantic identities explicitly in both
   parsers.
4. Keep flag material out of model-addressable scratch storage. The worker
   should not read the runtime flag unless a separate success condition has
   already been established.
5. Differentially test the Python and native parsers with the same malformed,
   extension, collision, and boundary cases.

## Flag

```text
zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}
```
