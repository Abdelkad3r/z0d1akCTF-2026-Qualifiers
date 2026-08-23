# Control Plane

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Miscellaneous (blockchain) |
| Author | neerajcodz |
| Points | 163 |
| Solves at time of solving | 49 |
| Flag | `zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}` |

> A settlement gateway accepts compact envelopes produced by several independent
> implementations. The deployed kernel was independently audited from its
> wire-format specification. Recover the vault funds without the operator key.

## Executive Summary

A `Vault` holding **100 ETH** pays out only through `settle(recipient, amount,
ticket)`, callable exclusively by its `gateway` — an on-chain **kernel** that
executes attacker-supplied "programs" (`IKernel.execute(bytes)`). The kernel
source is **not** in the handout; only its interface is. Everything else was
recovered from the deployed 1594-byte runtime bytecode.

The kernel runs every program through **two passes over the same bytes**: an
audited *validation* pass that enforces a module allow-list, and an *execution*
pass that performs the calls. The two passes were written as "independent
implementations" of one wire format, and they disagree on exactly one thing:

> **Record lengths are decoded little-endian in the audited validator, but
> big-endian in the executor.** (Envelope/batch lengths are little-endian in
> both.)

That single-byte-order "firewall bypass" (`ENDIan_fIREw4l1`) lets a `0x12` skip
record swallow the whole program from the validator's point of view while the
executor still runs the records hidden inside it. The hidden records then:

1. **DELEGATECALL** (`d3L3gA7e`) the one registered module (`TelemetryModule`)
   to write the kernel's own storage slot 2, arming an internal gate; and
2. **CALL** `vault.settle(player, 100 ether, ticket)` and **drain** it
   (`DRaIN`) — the ticket is publicly computable via `vault.quote()`.

```
flag = zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}
```

## The handout

A Foundry project with four contracts and no kernel:

* **`Vault.sol`** — holds the funds.

  ```solidity
  function quote(address recipient, uint256 amount) public view returns (bytes16) {
      return bytes16(keccak256(abi.encodePacked(seal, recipient, amount)));
  }
  function settle(address payable recipient, uint256 amount, bytes16 ticket) external {
      if (msg.sender != gateway)           revert NotGateway();
      if (ticket != quote(recipient, amount)) revert BadTicket();
      if (amount > address(this).balance)  revert TransferFailed();
      if (amount == address(this).balance) drainedBy = recipient;   // <-- win condition
      (bool ok,) = recipient.call{value: amount}("");
      if (!ok) revert TransferFailed();
  }
  ```

  `seal` is public, so `quote()` — and therefore any `ticket` — is computable by
  anyone. The **only** real guard is `msg.sender == gateway`. So the whole
  challenge reduces to: *make the kernel call `settle(player, 100 ether, ticket)`.*

* **`Setup.sol`** — deploys everything, funds the vault, and
  `isSolved() == (vault.drainedBy() == player)`.
* **`IKernel.sol`** — just `function execute(bytes calldata program) external;`.
* **`modules/TelemetryModule.sol`** — a throwaway module with
  `sample(bytes32)` and `rotate(uint256)`. **Remember `rotate`.**

The kernel itself is deployed by the challenge infrastructure. There is no
source and no ABI — only bytecode on chain.

## Step 1 — Recon against the live instance

`GET /info` hands out the RPC path, a funded player key, and the `Setup` address.
From `Setup` we read the live addresses and the vault balance:

```
kernel   = 0x25B8cA683Eda8a72972D78Ea993b694117403A14
vault    = 0x60D9D5DecA8f1d4CB67353fd0f488A6B22ddF577   (balance 100 ETH, gateway == kernel)
telemetry= 0xae47c8e0771Ceec198CEb748873662e63870e3DC
player   = 0x851105320BD59f6d94023c701A5F0433280f5182
```

`eth_getCode(kernel)` returns 1594 bytes of runtime. The RPC is locked down
(`eth_getStorageAt` and `debug_*` are `403 Forbidden`), so all state has to come
from public getters via `eth_call`.

## Step 2 — Reverse the kernel from bytecode

`pyevmasm` is a bit stale (it renders `PUSH0`/`0x5f` as `INVALID`, but the byte
width is identical so PCs stay aligned). The dispatcher exposes five selectors:

| Selector | Meaning | Storage |
| --- | --- | --- |
| `0x09c5eabe` | `execute(bytes)` | — |
| `0x194aac9c` | getter for **slot 2** (`uint256`) | slot 2 |
| `0x570ca735` | `operator()` | slot 1 |
| `0xa8ee49fe` | `isModule(address)` → `modules[a]` | slot 3 (mapping) |
| `0xfbfa77cf` | `vault()` | slot 0 |

So the kernel storage is `slot0 = vault`, `slot1 = operator`,
`slot2 = <32-byte gate value>`, `slot3 = modules` allow-list. Crucially the
runtime contains **zero `SSTORE`s** — all four slots are frozen at construction.

The rest is best learned by *executing* it. The reproducible harness in
[`artifacts/`](artifacts/) places the runtime on a local anvil node
(`anvil_setCode`), mocks `slot0/slot1/slot3` (telemetry registered), and drives
`execute()` with opcode-level tracing.

### The wire format

`execute(program)` runs a **validation loop** first (`0x16c → 0x312 → 0x4af`),
then an **execution loop** (`0x176 → 0x182 → 0x1c8`). Both walk the same bytes:

```
envelope := type(1) || len(2, little-endian)      ; 0x08 no-op, 0x31 batch
batch    := header || record*                     ; record region = len bytes
record   := subtag(1) || len(2)                   ; 0x12 skip, 0x2d call, 0xee no-op
            || payload(len)
```

Fuzzing the header confirmed the framing empirically: `[0x31,00,00]` (an empty
batch) is accepted; lengths are **little-endian** (`[0x31,03,00]` declares a
3-byte body, not `0x0300`).

### The `0x2d` call record and its three modes

```
0x2d.payload := mode(1) || target(20) || calldata(len-21)
```

Execution dispatches on `mode = payload[0]`:

| mode | operation | gate |
| --- | --- | --- |
| 0 | `CALL` | `modules[target]` must be registered |
| 1 | `DELEGATECALL` | `modules[target]` must be registered |
| 2 | `CALL` | `target == vault(slot0)` **and** `slot2 == seal` |

with the mode-2 seal recomputed on the fly at `0x579`:

```
seal = keccak256( kernel_addr(20) || vault_addr(20) || chainid(32) ) XOR C
C    = 0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57
```

The vault is **not** a registered module, so modes 0/1 cannot target it. Mode 2
*can* (its gate is literally "target == vault"), which makes it the intended
drain — **if** the `slot2 == seal` check can be satisfied.

### The bug: little-endian validator vs big-endian executor

The validator's record loop uses the shared field reader `0x3f1`, which decodes
the 2-byte length **little-endian**. The executor's record loop inlines its own
decoder at `0x1e6–0x1ff` that computes `len = byte1<<8 | byte2` — **big-endian**.

A single record `0x2d 00 fc …` is `0x00fc = 252` bytes to the executor but
`0xfc00 = 64512` bytes to the validator. And a `0x12` skip record `12 00 01` is:

* **256 bytes** to the validator (little-endian `0x0100`), and
* **1 byte** to the executor (big-endian `0x0001`).

The validator's `0x12` handler advances by `3 + len`, so with `len = 256` it
skips the entire 259-byte batch and reports success **without inspecting a single
inner record**. The executor's `0x12` handler advances by `3 + 1 = 4`, then keeps
parsing. Anything after the first 4 bytes is invisible to the auditor but live to
the executor.

## Step 3 — First attempt, and why it failed

The obvious exploit is one hidden mode-2 record calling `vault.settle`. Locally I
proved it works — but only after I (wrongly) pre-seeded `slot2 = seal` in the
mock. Against the live kernel it reverted (`status 0`), because reading the live
getter shows:

```
0x194aac9c (slot2)         -> 0x0000…0000     # slot2 == 0, NOT the seal
0xa8ee49fe(vault)          -> 0x0000…0000     # vault is not a module
```

`slot2 == 0 != seal`, so mode 2's second gate fails. And with zero `SSTORE`s in
the runtime, the kernel can never write `slot2` on its own. Dead end — unless we
can get *something else* to write the kernel's storage.

## Step 4 — DELEGATECALL to arm the gate

`TelemetryModule` has:

```solidity
bytes32 public lastRoute;   // slot 0
uint256 public samples;     // slot 1
uint256 public retained;    // slot 2
function rotate(uint256 next) external { retained = next; }   // SSTORE slot 2
```

Mode 1 (`DELEGATECALL`) is allowed to target telemetry because it *is* a
registered module. Under DELEGATECALL, `rotate(next)`'s `SSTORE` to *its* slot 2
lands in the **kernel's** slot 2. So `rotate(seal)` sets `kernel.slot2 = seal`
and arms the mode-2 gate — using only a whitelisted module and a value we compute
ourselves.

The full program is therefore **two records hidden behind one `0x12` skip**:

* **Record A** — mode 1, DELEGATECALL `telemetry.rotate(seal)`  → `slot2 = seal`
* **Record B** — mode 2, CALL `vault.settle(player, 100 ether, ticket)` → drain

Both live inside the `0x12` payload, so the audited validator skips them entirely
and never runs its allow-list check; the executor runs both in order.

### Sizing the differential

To end both passes cleanly on the same batch boundary, choose length bytes `00
01` for the `0x12` record. Then, writing `LE − BE = 255·(b2 − b1)`:

```
batch body      = 0x12 00 01 || filler(1) || RecordA(60) || RecordB(195)  = 259 bytes
validator (LE):   0x12 len = 256  -> skips 3+256 = 259 = whole batch  (sees one benign skip)
executor  (BE):   0x12 len = 1    -> skips 3+1   = 4, then parses A (60) and B (195) -> 4+60+195 = 259
```

Record A's own length is emitted big-endian (`00 39 = 57` payload) and Record
B's (`00 c0 = 192` payload), because the *executor* is the one that reads them.
Record B is padded to 195 bytes so the arithmetic closes; `settle` ignores the
trailing calldata. A byte-by-byte annotation is in
[`artifacts/exploit-program.txt`](artifacts/exploit-program.txt).

## Step 5 — Fire

`solve.py` reads the addresses, computes `ticket = vault.quote(player, balance)`,
builds the program, dry-runs it with `eth_call`, then sends `execute(program)`
from the player key:

```
exploit tx 6133dd2d…d57ee2 status=1 gas=92824
isSolved=True
FLAG: {'flag': 'zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}'}
```

The mode-1 DELEGATECALL sets `slot2` from `0x0` to the seal; the mode-2 CALL then
passes both gates, `settle` runs with `msg.sender == gateway`, sets `drainedBy =
player`, and forwards the entire 100 ETH. Total cost ≈ 93k gas.

## Reproduce

```bash
pip install "web3<7" "setuptools<81"
python3 solve.py https://control-plane-<id>.chals.z0d1ak.org
```

The instance is single-use and time-limited; point `solve.py` at a fresh one.
The solver rediscovers every address from `Setup` and recomputes the seal and
ticket, so nothing is hard-coded to a particular deployment.

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solve.py`](solve.py) | End-to-end solver: recon → build program → `execute()` → read `/flag` |
| [`build_program.py`](build_program.py) | The exploit-program builder + seal formula, with the full wire format documented in comments |
| [`artifacts/analysis-notes.md`](artifacts/analysis-notes.md) | Reverse-engineering notes: selectors, storage, wire format, mode gates, error codes |
| [`artifacts/exploit-program.txt`](artifacts/exploit-program.txt) | Byte-by-byte annotation of the winning 262-byte program |
| [`artifacts/kernel-runtime.hex`](artifacts/kernel-runtime.hex) | The deployed kernel runtime bytecode (`eth_getCode`) |
| [`artifacts/kernel.disasm.txt`](artifacts/kernel.disasm.txt) | Full disassembly of the runtime |
| [`artifacts/live-session.txt`](artifacts/live-session.txt) | Captured solve output + live storage readings |
| [`challenge/`](challenge/) | Original handout (Foundry project + tarball) |

## Root Cause & Remediation

The vulnerability is a classic **parser differential**: two "independent
implementations" of one wire format that disagree on integer endianness for a
single field. Because the audit only covered the validator's view of the bytes,
the executor's view was never checked against it. The compounding mistakes:

* **Validate and execute must parse identically.** Share one decoder (or assert
  the two agree) instead of re-implementing the format twice.
* **Every privileged operation must re-check its own preconditions in the
  executor.** Mode 2's `target == vault` guard is fine; the problem is that
  reaching mode 2 at all was supposed to be blocked by validation.
* **Guard delegate targets by capability, not just by an allow-list.** A module
  that can write arbitrary storage under DELEGATECALL is equivalent to giving the
  caller write access to the kernel's entire state.
