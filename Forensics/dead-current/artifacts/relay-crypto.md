# `relay` binary — recovered crypto internals

`relay` is a **Go 1.26.5** static, ELF-stripped binary. Go keeps its own symbol
table in `.gopclntab`, so `pcln.py` recovers `main.*` function names/addresses
even though `readelf`/`go tool objdump` see "no symbol section".

## Relevant functions (VA = 0x401000 + entryoff)

| Function | VA | Role |
| --- | --- | --- |
| `main.deriveIncidentKey` | `0x4a3d40` | per-incident key derivation |
| `main.xorStream`         | `0x4a3e40` | stream cipher (SHA-256 keystream) |
| `main.marshalQueue`      | `0x4a3c60` | builds the `QMSG` socket packet |
| `main.queueDigest`       | `0x4a2f80` | CRC over the queue packet |
| `main.selfTest`          | `0x4a3fa0` | exercises the crypto with test vectors |
| `main.main`              | `0x4a45e0` | prints "no live transport" and exits |
| `crypto/sha256.Sum256`   | `0x490a40` | primitive used by both crypto routines |

`main.selfTest` is never reached at runtime (an `init()` bails out first), so the
crypto was observed by running the binary under gdb and `jump`-ing into
`selfTest`, then breaking on the `Sum256` calls.

## Ground truth (captured with gdb, on selfTest's test vectors)

`main.deriveIncidentKey` hashes a 56-byte buffer:

```
SHA256( state32[32] || streamID[16] || ctx8[8] )   ->  incidentKey[32]

test inputs:
  state32  = SHA256("deleted incident key") = 54c32195...6df01345
  streamID = "PELAGOS\0\0\0\0\0\0\0\0\0"           (16 bytes)
  ctx8     = "SOGALEP\0"                            (8  bytes)
  result   = 9684d62ecc1c2fde6eed258465bacb3ad1ec2edb4ebf253b74155e55ade10f50
```

`main.xorStream` is a SHA-256 counter-mode keystream:

```
keystream[i] = SHA256( incidentKey[32] || uint32_le(i) )   # 32 bytes per block
plaintext    = ciphertext XOR keystream

verified: ct[0:8] = pt[0:8] ^ SHA256(incidentKey||0)[0:8]  matched exactly
```

The rodata labels `"captured relay state"` and `"deleted incident key"` are the
two 32-byte secret fields of the serialized `RelayState`.

## Mapping to the real incident (from the checkpoint)

- `streamID` = the incident's stream token `1dcd1906f764dba6b7a054970cd95e17`
  (present both in the `QMSG` packet and the `IRF1` record).
- `ctx8`     = the first 8 bytes of the `IRF1` record nonce = `42ca22ec2ed69c97`.
- `state32`  = the live `RelayState` master secret recovered from process memory
  (`pages-2.img`), sitting immediately after the empty `{type=4,len=0}` incident
  record marker: `07393d2c...34f02247`.
