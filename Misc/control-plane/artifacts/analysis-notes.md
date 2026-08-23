# Control Plane — reverse-engineering notes

The kernel is **not** shipped in the handout; it is a deployed contract whose
`IKernel.execute(bytes)` interface is the only thing given. Everything below was
recovered from its 1594-byte runtime bytecode (`kernel-runtime.hex`,
disassembled in `kernel.disasm.txt`) plus opcode-level tracing against a local
anvil node with the runtime `anvil_setCode`'d in and storage mocked.

## Function selectors (dispatcher @ 0x00–0x4c)

| Selector | Meaning | Handler |
| --- | --- | --- |
| `0x09c5eabe` | `execute(bytes)` | `0x64 → 0x16a` |
| `0x194aac9c` | getter for **slot 2** (`uint256`) | `0xbd` |
| `0x570ca735` | `operator()` → **slot 1** | `0xda` |
| `0xa8ee49fe` | `isModule(address)` → `modules[a] != 0`, mapping at **slot 3** | `0x102` |
| `0xfbfa77cf` | `vault()` → **slot 0** | `0x143` |

## Storage layout

| Slot | Contents |
| --- | --- |
| 0 | `vault` (the settlement target; also the Vault's `gateway`) |
| 1 | `operator` |
| 2 | a 32-byte value gating mode-2 calls (**== 0** on the live deployment) |
| 3 | `mapping(address => bool) modules` (allow-list; only `TelemetryModule` registered) |

The runtime contains **zero `SSTORE`s** — all storage is fixed at construction.

## `execute(bytes)` = validate-then-execute (two passes over the same bytes)

`0x16a` sets `i=0` and runs a **validation loop** (`0x16c → 0x312 → 0x4af`), then
resets `i=0` and runs an **execution loop** (`0x176 → 0x182 → 0x1c8`).

### Compact wire format

```
envelope := type(1) || len(2, little-endian)      ; 0x08 = no-op, 0x31 = batch
batch    := envelope-header || record*            ; record region length = len
record   := subtag(1) || len(2)                   ; 0x12 skip, 0x2d call, 0xee no-op
            || payload(len)
```

The shared field reader `0x3f1` decodes envelope headers **little-endian in both
passes**. Record headers, however, are decoded by two different code paths:

* validator record loop `0x4c1` uses `0x3f1` → **little-endian**;
* executor record loop `0x1da` inlines its own decoder at `0x1e6–0x1ff`:
  `len = byte1<<8 | byte2` → **big-endian**.

**This is the bug.** A record whose length bytes are `00 01` is 256 bytes long to
the validator and 1 byte long to the executor.

### `0x2d` call record

`payload := mode(1) || target(20) || calldata(len-21)` with:

* executor `target` read at `record+4` (= `payload[1:21]`), calldata copied from
  `record+24` with length `record_len-21`, `mode` read at `record+3` (=`payload[0]`);
* validator reads its allow-list address at `record+1` and requires `payload[0]==0`.

Execution mode dispatch (`0x26a`):

| mode | op | gate |
| --- | --- | --- |
| 0 | `CALL` | `modules[target]` must be registered |
| 1 | `DELEGATECALL` | `modules[target]` must be registered |
| 2 | `CALL` (+value) | `target == vault(slot0)` **and** `slot2 == seal` |

### Mode-2 seal (`0x579`)

```
seal = keccak256( kernel_addr(20) || vault_addr(20) || chainid(32) ) XOR C
C    = 0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57
```

## Custom error selectors (for reference)

| Revert selector | Raised when |
| --- | --- |
| `0x241116f7` | field read past end of buffer (truncated) |
| `0x534bae78` | bad envelope type / bad record subtag |
| `0x82d5d76a` | `0x2d` target not a registered module (validator) |
| `0x84e505d2` | `0x2d` record region too small / flags byte non-zero (validator) |

## Exploit chain

1. The validator only allows `0x2d` records that target a registered module and
   have `mode == 0`. Mode 2 is therefore **unreachable through validation**.
2. Wrap the malicious records in a `0x12` skip record with length `00 01`:
   * validator (LE=256) treats the whole 259-byte batch as one skipped record —
     it never inspects anything inside;
   * executor (BE=1) skips only 4 bytes, then runs the hidden records.
3. Hidden **record A** (mode 1) DELEGATECALLs the registered `TelemetryModule`.
   `rotate(uint256)` writes the module's slot 2 (`retained`); under DELEGATECALL
   that is the **kernel's** slot 2. Set it to `seal` → the mode-2 gate is armed.
   (Passes execution's own `modules[telemetry]` check.)
4. Hidden **record B** (mode 2) CALLs `vault.settle(player, balance, ticket)`.
   `target == vault` ✓, `slot2 == seal` ✓. `ticket = vault.quote(player, balance)`
   is public. `settle` runs with `msg.sender == kernel == gateway`, sets
   `drainedBy = player`, and transfers the full balance ⇒ `Setup.isSolved()`.
