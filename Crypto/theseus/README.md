# THESEUS

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Cryptography |
| Author | AncientDragon |
| Points | 154 |
| Solves at time of solving | 57 |
| Flag | `zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}` |

> One address. Five hulls. Four funerals. The ledger remembers what the
> bytecode forgets.

## Executive Summary

THESEUS is an Ethereum history and authenticated-data challenge built around a
single EIP-1967 proxy. The proxy keeps one address while its implementation is
replaced five times. Four old implementations are destroyed, but the proxy's
storage, transaction history, and event logs remain.

The final implementation exposes this function:

```solidity
function unlock(
    bytes32 firstMark,
    bytes32 secondMark,
    bytes32 selectedLeaf,
    bytes32[3] calldata siblings,
    bytes32 stateProofMark,
    bytes32 blockWitnessMark,
    bytes32 executionMark
) external;
```

The intended-looking path involves reconstructing historical ledger records,
Merkle proofs, storage proofs, block witnesses, receipt proofs, and an execution
trace. Most of that complexity is unnecessary. The crucial observation is that
the final hull compares the submitted values with commitments already retained
in the proxy's storage:

- the first and second historical marks are in slots `2` and `3`;
- the authenticated ledger root is in slot `4`;
- the selected ledger leaf and proof salt are in slots `8` and `9`;
- the expected block and execution witness marks are in slots `10` and `11`.

Only the three-node Merkle path and one state commitment must be reconstructed.
The deployed `Chart` program decodes the eight historical ledger events and
returns the exact path. The state commitment is:

```text
keccak256(firstMark || secondMark || harbourRoot || proofSalt)
```

Submitting those values opens the final hull. The literal flag is then recovered
from the immutable blockchain history: it is embedded in the `Setup` contract's
creation input.

The supplied [`solve.py`](solve.py) performs the complete attack against a fresh
instance. [`verify_offline.py`](verify_offline.py) independently reconstructs
the Merkle tree and state commitment from the preserved solve artifacts.

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/crypto_theseus.tar.gz`](challenge/crypto_theseus.tar.gz) | Original challenge handout | `6ef86ab3341f3118dc89875a086ba2f6591579767c43900cae68875cb3af2b25` |
| [`challenge/interfaces/ITheseus.sol`](challenge/interfaces/ITheseus.sol) | Final proxy interface | `22de1cd40a12e7c2dcdd54913fa191292aefa9e4efab4702e989b7d257301fe1` |
| [`challenge/interfaces/IChartProgram.sol`](challenge/interfaces/IChartProgram.sol) | Historical ledger decoder interface | `8d799825cde95ffa34cfa28dda55779ca3ab12beba84b97e1baf3aafe7a8b2a6` |
| [`challenge/interfaces/IBlockWitnessProgram.sol`](challenge/interfaces/IBlockWitnessProgram.sol) | Block and receipt witness interface | `375ea1875b44250c5114dc4792b6d514e55b8e53a88d7d1b0c8c8e16ef4be4cd` |
| [`challenge/interfaces/IExecutionWitnessProgram.sol`](challenge/interfaces/IExecutionWitnessProgram.sol) | Execution trace witness interface | `88dec161e13b07811ae4b952dda6807a409952f222d5c3f825714d1a6f97ea23` |
| [`challenge/interfaces/ISetup.sol`](challenge/interfaces/ISetup.sol) | Setup and solved-state interface | `de8da02a367217c19f9e5fa0138aebf9173dce7c4f59a3390367c53a29392a86` |
| [`solve.py`](solve.py) | End-to-end solver for a fresh instance | `27c028dddcf2bb56c49c133937a55453bb0cd46ce896ccf6b2d2393b60e91da6` |
| [`verify_offline.py`](verify_offline.py) | Offline Merkle, commitment, and flag verifier | `82fb27908ebc8d355469f5756f57d98a8c55281c11539aff07f1cd91b475cc0f` |
| [`artifacts/ledger-records.json`](artifacts/ledger-records.json) | Eight reconstructed canonical ledger records | `64936bd7a0babf6993bf41ee0dd02e4f993ec6aa0f49bb7a5571de399ef620bf` |
| [`artifacts/accepted-solution.json`](artifacts/accepted-solution.json) | Exact accepted proof values and transaction IDs | `6dff8c633db0f3e226512e0bd88e8b4b4f797d22559509cd7da07306c03fbe8d` |
| [`artifacts/setup-deployment-flag-fragment.hex`](artifacts/setup-deployment-flag-fragment.hex) | Flag-bearing fragment from Setup creation data | `1498833a266e43601d08b11224608dc5ccbc230000bc5f274290e7dbeebdfc0d` |
| [`artifacts/remote-run.txt`](artifacts/remote-run.txt) | Successful live solve transcript | `87f891c14e0b9361c3223b69d4840de6b03cfdba8b6a4605d28c8d95e9b9fb0c` |

The instancer hostname expires. The artifacts intentionally omit the temporary
player private key while preserving every public value needed to audit the
solution.

## 1. Handout Triage

The archive contains five Solidity interfaces and no implementation source:

```console
$ tar -tzf crypto_theseus.tar.gz
crypto_theseus/IBlockWitnessProgram.sol
crypto_theseus/IChartProgram.sol
crypto_theseus/IExecutionWitnessProgram.sol
crypto_theseus/ISetup.sol
crypto_theseus/ITheseus.sol
```

The setup interface gives us the proxy and player addresses:

```solidity
interface ISetup {
    function target() external view returns (address);
    function player() external view returns (address);
    function isSolved() external view returns (bool);
}
```

The endpoint serves two roles. An HTTP `GET` returns the instance metadata and
temporary player key, while JSON-RPC requests sent with `POST` expose the local
Anvil chain. Therefore the chain itself is the missing implementation handout.

For the captured solve:

```text
Setup   0x9e545e3c0baab3e08cdfd552c960a1050f373042
Target  0xe7f1725e7734ce288f8367e1bb143e90bb3f0512
Player  0x70997970c51812dc3a010c7d01b50e0d17dc79c8
```

## 2. One Address, Five Hulls

The target's implementation is stored in the standard EIP-1967 slot:

```text
0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
```

Following deployment and upgrade transactions reveals five implementations:

```text
0x5fbdb2315678afecb367f032d93f642f64180aa3
0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9
0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6
0x4ed7c70f96b99c776995fb64377f0d4ab3b0e1c1
0x67d269191c92caf3cd7723f116c85e6e9bf55933
```

The first four have no runtime code in the latest state because they were
destroyed after use. Their effects do not disappear: calls made through the
proxy wrote into the proxy's storage, and historical receipts still contain
their logs. This is the Ship of Theseus clue in concrete form. Contract identity
cannot safely be reduced to its current address and bytecode.

The final implementation is the fifth address. Disassembling its dispatcher and
`unlock` path gives the storage layout below.

## 3. Proxy Storage Map

| Slot | Meaning |
| ---: | --- |
| `0` | Player address and `opened` flag, packed |
| `1` | Owner address |
| `2` | First historical mark |
| `3` | Second historical mark |
| `4` | Authenticated ledger root (`harbourRoot`) |
| `5` | `Chart` program address |
| `6` | `BlockWitness` program address |
| `7` | `ExecutionWitness` program address |
| `8` | Selected ledger leaf |
| `9` | State-proof salt |
| `10` | Expected block witness mark |
| `11` | Expected execution witness mark |

The associated helper programs in the captured instance were:

```text
Chart             0xc6e7df5e7b4f2a278906862b61205850344d4e7d
BlockWitness      0x7a2088a1bfc9d81c55368ae168c2c02570cb814f
ExecutionWitness  0x09635f643e140090a9a8dcd712ed6285858cebef
```

Reading proxy storage is legitimate chain analysis, not a local-only shortcut.
Ethereum contract storage is public, and `eth_getStorageAt` works on the live
challenge endpoint.

## 4. Recovering the Ledger

Historical logs contain one batch of eight records emitted at checkpoint block
`13`. Every log has:

- the same emitting proxy;
- the same event signature topic;
- an indexed record number from `0` through `7`;
- one `bytes32` value in the event data.

The canonical input expected by `Chart.decode` is not merely the event data. It
is the one-byte record index concatenated with that data:

```text
canonicalRecord[i] = uint8(i) || eventData[i]
```

For example, record three is:

```text
index       = 03
event data  = e4b7c0a895378a9c02905c6f13174f06f76ac25307368430d9ca931d7bc4d029
record      = 03e4b7c0a895378a9c02905c6f13174f06f76ac25307368430d9ca931d7bc4d029
```

All eight values are preserved in
[`artifacts/ledger-records.json`](artifacts/ledger-records.json). The solver
finds this batch structurally, by grouping logs on `(event topic, block)` and
requiring the complete index set `{0,...,7}`. It does not hardcode the event
signature or block number.

## 5. Decoding the Chart

The chart address is the low 20 bytes of slot `5`. Calling its supplied ABI with
the two stored marks, player address, and canonical records returns:

```text
harbourRoot:
  8f6cbf57efe0320a9d4310abf4fac350b410eefd53be1807e4334a29c43dfc92

selectedLeaf (record 3):
  4b7184e7237843f59cd13cd23b30956e03d63a24a5dc7a5e59306177fd8307cc

siblings:
  9292bd54c28dd089a197d06eb72d82b21b2160d7af761e93145804e9865b736a
  6167c12f47153e4f135a993d4fd5d2145d067fa495baa8d73512d67bdf0b5166
  94a415d37e2bdf438906a7a9440f97b158b946ee77ae468328a10892acca2a4e

checkpointBlock = 13
```

It also returns three storage-proof keys, the corresponding expected values
`(firstMark, secondMark, harbourRoot)`, and this proof salt:

```text
ae721baf70752ca7c319b357a4735e70c76bffc958b57f1dc471fb2b6e4cf934
```

Those keys belong to the longer state-witness route. The final exploit does not
need to serialize a Merkle Patricia proof because the final hull only compares
the derived commitment shown below.

## 6. Verifying the Merkle Path

Each leaf is the Ethereum Keccak-256 hash of one canonical record:

```text
leaf[i] = keccak256(canonicalRecord[i])
```

Adjacent nodes are concatenated left-to-right and hashed without sorting:

```text
parent = keccak256(left || right)
```

Eight leaves produce three levels. Record `3` is the selected leaf, so the path
uses left/right order according to the low bit of the current index:

```python
node = selected_leaf
index = 3
for sibling in siblings:
    if index & 1:
        node = keccak256(sibling + node)
    else:
        node = keccak256(node + sibling)
    index >>= 1
```

The resulting root is exactly:

```text
0x8f6cbf57efe0320a9d4310abf4fac350b410eefd53be1807e4334a29c43dfc92
```

This matches both `Chart.decode` and target storage slot `4`.

## 7. Rebuilding the State Mark

The final hull checks a four-word commitment. Because every field is exactly
`bytes32`, packed concatenation and canonical ABI encoding have the same byte
layout here:

```text
stateProofMark = keccak256(
    firstMark || secondMark || harbourRoot || proofSalt
)
```

For the captured instance:

```text
firstMark  = 02a89479ded787c07779f72cd9038d5cd7a6efbcf112cd56e411c71dd31ea78c
secondMark = 27ce1bbda6f13d9836bfab6e3d0b2312fe55647d1849a78afc5e340310ebad50
root       = 8f6cbf57efe0320a9d4310abf4fac350b410eefd53be1807e4334a29c43dfc92
salt       = ae721baf70752ca7c319b357a4735e70c76bffc958b57f1dc471fb2b6e4cf934
```

The commitment is:

```text
0x5222ca9207cfcc6aad199f8777f69353f557eec01035575b452aa927f2a10401
```

## 8. Avoiding the Witness Rabbit Hole

The handout strongly encourages reconstructing a selected raw transaction,
transaction and receipt Merkle proofs, a runtime trace, and a trace digest. The
`BlockWitness` and `ExecutionWitness` interfaces make that route appear
mandatory.

It is not. The final hull receives only the resulting `bytes32` marks and checks
them against the values established earlier in the proxy lifecycle. Those
expected values remain directly readable in slots `10` and `11`:

```text
blockWitnessMark =
  0x192ce05b9e753da0d59419c95cf5f8eef51d0ec9a3e6e7073b7bf063c841fbdf

executionMark =
  0x2b9754f4219c39b327a385955e788bad551f93791000e594eb87842ade7bba77
```

This is the central exploit. A verifier cannot treat a secret-looking
commitment as secret merely because the preimage procedure is elaborate. If the
accepted commitment itself is stored publicly and the caller may submit it
verbatim, the proof has become a bearer token.

## 9. Opening the Final Hull

With all seven arguments known, call `unlock` from the player account:

```text
unlock(
    firstMark,
    secondMark,
    selectedLeaf,
    siblings,
    stateProofMark,
    blockWitnessMark,
    executionMark
)
```

The captured transaction was:

```text
0x53d9d8e67bde9db71ab23e75133cd6e31e5956c19e1bd7d336730237540c717d
```

Its receipt status is `1`, `opened()` becomes `true`, and the setup confirms:

```text
Setup.isSolved() = true
```

## 10. Recovering the Literal Flag

Opening the proxy satisfies the challenge, but the target does not return the
flag as ordinary call output. The flag belongs to the `Setup` deployment. Since
creation transactions are part of immutable history, scan blocks for a
contract-creation receipt whose `contractAddress` equals the setup address.

For the captured chain, that transaction was in block `27`:

```text
0x94571d0d262a0b4b8fc8549641994280815b0eddf31aca557cfcc8e71e0ab08a
```

Decode its input as bytes and search the constructor arguments for `zdk{...}`.
The printable fragment is:

```text
-zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}
```

Therefore the flag is:

```text
zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}
```

The platform accepted this exact value with `The flag is correct.`

## 11. Running the Solver

Requirements:

- Python 3.10 or newer;
- Foundry's `cast` command;
- an active THESEUS instance URL.

Run:

```console
$ cd Crypto/theseus
$ python3 solve.py https://theseus-<instance-id>.chals.z0d1ak.org
[*] setup  = 0x...
[*] target = 0x...
[*] player = 0x...
[+] canonical records : 8
[+] checkpoint block  : 13
[+] harbour root      : 0x...
[+] selected leaf     : 0x...
[+] state proof mark  : 0x...
[+] block witness mark: 0x...
[+] execution mark    : 0x...
[+] unlock transaction: 0x...
[+] Setup.isSolved() = true
[+] FLAG: zdk{...}
```

Use `--inspect-only` to derive and print the proof without sending a
transaction:

```console
$ python3 solve.py --inspect-only https://theseus-<instance-id>.chals.z0d1ak.org
```

The solver deliberately discovers instance-specific addresses, blocks, event
topics, records, and commitments at runtime. It does not reuse the captured
instance values.

## 12. Offline Verification

After the instance expires, reproduce the cryptographic checks from the saved
evidence:

```console
$ python3 verify_offline.py
[+] 8 ledger leaves -> 0x8f6cbf57efe0320a9d4310abf4fac350b410eefd53be1807e4334a29c43dfc92
[+] Merkle path for leaf 3 verified
[+] state proof mark -> 0x5222ca9207cfcc6aad199f8777f69353f557eec01035575b452aa927f2a10401
[+] flag -> zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}
```

Do not replace Ethereum Keccak-256 with Python's `hashlib.sha3_256`; they use
different padding and produce different digests. The verifier calls `cast
keccak` explicitly to avoid that common mistake.

## Takeaways

1. **An address is a location, not an identity.** A proxy can host multiple
   implementations over time while retaining one address and one storage
   namespace.
2. **Destroyed bytecode does not erase history.** Earlier transactions, logs,
   receipts, and proxy-side state remain available.
3. **Public commitments are not authorization secrets.** Comparing a submitted
   value to a publicly stored hash only proves that the caller copied it.
4. **Inspect the final verifier before implementing every advertised proof.**
   Interfaces describe possible workflows; the final comparison determines
   what is actually required.
5. **Deployment input is evidence.** Constructor arguments and embedded strings
   remain recoverable from the creation transaction even when runtime code never
   exposes them.
