# Protocol and WASM Notes

## Browser PPJB wrapper

The public browser codec exports `r`, `a`, `w`, `o`, and the otherwise unused
`x`. Export `w` creates a browser job with this header:

| Offset | Size | Encoding | Meaning |
| ---: | ---: | --- | --- |
| `0x00` | 4 | ASCII | `PPJB` |
| `0x04` | 2 | little-endian | version `3` |
| `0x06` | 2 | big-endian | metadata length |
| `0x08` | 4 | big-endian | payload length |
| `0x0c` | 4 | big-endian | CRC32C of metadata and payload |

Each metadata field is:

```text
u8 name_length || u8 value_length || be32 FNV1a(name) || name || value
```

The browser emits `label`, `center`, `radius`, and `strategy`. `center` is half
the payload length, `radius` is one quarter of the payload length, and the only
public strategy is `1`.

## MOZ1 response

The worker returns a `MOZ1` capsule containing a middle-out ordered RLE stream.
The first 20 bytes hold the magic, version, method, radius, output length,
packed length, and standard CRC32. The decoder first expands the RLE stream,
then maps sequential bytes around the midpoint in this order:

```text
middle, middle-1, middle+1, middle-2, middle+2, ...
```

## Hidden WSC4 decoder

The unused WASM export `x(capsule, 48, key, 8, output, 32)` validates:

```text
WSC4 || version=1 || slot || length=32 || method=1
     || CRC32(key) || 32-byte ciphertext || CRC32(first 44 bytes)
```

For byte index `i`, it computes:

```text
output[i] = key[(slot + i) & 7]
          ^ ((slot * 29 + 99 + 17 * i) & 0xff)
          ^ ciphertext[i]
```

The key commitment in every leaked capsule is `0x8b9ba950`, which equals the
CRC32 of the eight bytes obtained by hex-decoding the public build ID:

```text
build ID:       c3bdbf6cc7b7ef92
build key:      c3 bd bf 6c c7 b7 ef 92
CRC32:          8b 9b a9 50
```

The 32-byte outputs are Shamir shares over `GF(2^8)` with reduction polynomial
`x^8 + x^4 + x^3 + x + 1` (`0x11b`). Two of the four leaked records are real;
the other two are decoys. Testing each pair's interpolation at `x=0` against
the public trial-token HMAC identifies slots `209` and `123`.
