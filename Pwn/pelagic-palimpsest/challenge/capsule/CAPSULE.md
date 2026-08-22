# Sealed compiler capsule and dive certificate, version 1

The maker's plate is salt-eaten. Only `NUIT—` remains beside a Python coiled around a native anchor.

A sealed compiler capsule is a directory tree lowered from the surface build
station to Nereid-9. Paths use UTF-8 and `/` separators.
Symbolic links, non-regular files, and `capsule.json` are ignored. The manifest
describes provenance but is not executable input and is not part of the
correspondence comparison.

For ELF files, enumerate `PT_LOAD` segments in program-header order, discard
writable segments, concatenate neither segments nor files, and split each
remaining segment into zero-padded 4096-byte pages. Page indexes are assigned
consecutively within the ELF file. A non-ELF file is split directly into pages;
an empty file has one empty page.

Compare pages by `(relative path, page index)`. Each difference is encoded as:

```text
u16le(path length) || path || u64le(page index) ||
BLAKE3(suspect page) || BLAKE3(rebuilt page)
```

Leaves and internal nodes are domain separated with `palimpsest-leaf-v1\0` and
`palimpsest-node-v1\0`. Sort leaves by path and index. Duplicate an odd final
node at each level. The empty tree is `BLAKE3("palimpsest-empty-v1\0")`.

The network gate proves both the divergence result and possession of the clean
DDC stage-2 capsule. The server sends:

```text
"DIVE" || nonce[32] || u8(challenge count) || u16le(page index)...
```

Page indexes refer to the clean stage-2 compiler ELF pages enumerated by the
rules above. The client replies with:

```text
BLAKE2s("palimpsest-dive-proof-v2\0" || nonce || divergence root)
|| for each challenged index, in server order:
   BLAKE2s("palimpsest-page-possession-v2\0" || nonce ||
           u16le(page index) || clean stage-2 page)
```
