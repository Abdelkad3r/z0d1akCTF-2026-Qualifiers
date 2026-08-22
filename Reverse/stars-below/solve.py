#!/usr/bin/env python3
"""Offline solver for z0d1akCTF 2026 Qualifiers: stars-below.

The VM bytecode and expanded round schedules were dumped after the binary
decrypted them. They are kept in artifacts/ and authenticated below so this
script remains deterministic and reviewable.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import os
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_ARCHIVE = ROOT / "challenge" / "rev_stars-below.zip"
ARTIFACTS = ROOT / "artifacts"
MASK32 = 0xFFFFFFFF

EXPECTED_SHA256 = {
    "archive": "7fab84b9aa51fedadab2efb42b4606aa25011cdaacc0d3f6e625254c7be8d5b9",
    "binary": "111b8c3ed811ab5f1d87b0ef131110cd80ef33dba293cade5cdf1adb2dfe7e2c",
    "vma.bin": "69f4678ab8230007ef62532ff13d6a74db614f98b0c4efce455fd9d0451fadb2",
    "vmb.bin": "672555a51035478f376b01d963e09b70d6b4bb87b551824c9bab1df7fd1477d3",
    "vma-table.bin": "18283dc60c7fafb32a95546bd7b0d5f7649a58f48df1c52ac822b7b801fbd4cf",
    "vmb-table.bin": "81eea446295f57a11069908b913ee2b57ff29dda4fe280e672ec8719b26b4c11",
}

VM_A_OPCODES = bytes.fromhex("e9 9a e0 2c 5a 9b 50 b5 7c 65 35 93 74 90 0b")
VM_B_OPCODES = bytes.fromhex("4c 9d e7 b9 71 32 bd 8a a8 39 ed")
BASE32_ALPHABET = "87RJF2ACZLVUMXB3D6GH9WNSYP5QK4ET"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blake2s(*parts: bytes) -> bytes:
    digest = hashlib.blake2s()
    for part in parts:
        digest.update(part)
    return digest.digest()


def rol32(value: int, amount: int) -> int:
    amount &= 31
    value &= MASK32
    if amount == 0:
        return value
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def ror32(value: int, amount: int) -> int:
    amount &= 31
    value &= MASK32
    if amount == 0:
        return value
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def unpack_u32(data: bytes, offset: int, count: int) -> tuple[int, ...]:
    return struct.unpack_from(f"<{count}I", data, offset)


def load_handout(archive_path: Path) -> tuple[bytes, bytes]:
    archive = archive_path.read_bytes()
    if archive_path.resolve() == DEFAULT_ARCHIVE.resolve():
        assert sha256(archive) == EXPECTED_SHA256["archive"], "handout hash mismatch"
    with zipfile.ZipFile(archive_path) as handout:
        binary = handout.read("stars_below")
    assert sha256(binary) == EXPECTED_SHA256["binary"], "challenge binary hash mismatch"
    return archive, binary


def load_artifact(name: str) -> bytes:
    data = (ARTIFACTS / name).read_bytes()
    assert sha256(data) == EXPECTED_SHA256[name], f"{name} hash mismatch"
    return data


def recover_route(binary: bytes) -> str:
    route_constants = unpack_u32(binary, 0x77E0, 8)
    expected = 0xF06F770B

    def route_hash(route: tuple[int, ...]) -> int:
        state = 0x1799B0E8
        for position, fragment in enumerate(route):
            state ^= route_constants[fragment]
            state = rol32(state, fragment + 5 * position)
            state = (state + position + 0x9E3779B9) & MASK32
        return state

    matches = [
        route
        for route in itertools.permutations(range(8))
        if route_hash(route) == expected
    ]
    assert len(matches) == 1, f"expected one route, found {len(matches)}"
    return "".join(map(str, matches[0]))


def recover_callsign(binary: bytes, route: str) -> tuple[str, bytes]:
    fragments = binary[0x7660:0x7668].decode("ascii")
    callsign = "".join(fragments[int(index)] for index in route)
    encoded = callsign.encode("ascii")
    name_hash = blake2s(
        b"stars-below/name/v1\0",
        bytes([len(encoded)]),
        encoded,
    )
    guard = blake2s(
        b"stars-below/name-guard/v1\0",
        binary[0xC6C0:0xC6D0],
        name_hash,
    )
    assert guard == binary[0xC6A0:0xC6C0], "callsign guard mismatch"
    return callsign, name_hash


class Program:
    def __init__(self, bytecode: bytes, opcode_bytes: bytes):
        assert len(bytecode) % 8 == 0
        self.bytecode = bytecode
        self.opcodes = {encoded: logical for logical, encoded in enumerate(opcode_bytes)}

    def instruction(self, pc: int) -> tuple[int, int, int, int, int]:
        raw = self.bytecode[pc * 8:(pc + 1) * 8]
        return (
            self.opcodes[raw[0]],
            raw[1],
            raw[2],
            raw[3],
            struct.unpack_from("<I", raw, 4)[0],
        )


class RoundTable:
    RECORD_SIZE = 40

    def __init__(self, data: bytes, rounds: int):
        assert len(data) == rounds * self.RECORD_SIZE
        self.data = data

    @staticmethod
    def split_reference(reference: int) -> tuple[int, int]:
        return (reference >> 8) & 0xFF, reference & 0xFF

    def word(self, reference: int) -> int:
        round_index, constant_index = self.split_reference(reference)
        assert constant_index < 6
        offset = round_index * self.RECORD_SIZE + 8 + 4 * constant_index
        return struct.unpack_from("<I", self.data, offset)[0]

    def rotation(self, reference: int) -> int:
        round_index, rotation_index = self.split_reference(reference)
        assert rotation_index < 6
        return self.data[round_index * self.RECORD_SIZE + 32 + rotation_index]


def vm_a_forward(
    initial: list[int], program: Program, table: RoundTable
) -> list[int]:
    state = initial.copy()
    for round_index in range(24):
        base = round_index * 59
        for half_offset in (0, 24):
            pc = base + half_offset
            a, b, c, d = [program.instruction(pc + i)[4] & 7 for i in range(4)]
            k0 = table.word(program.instruction(pc + 4)[4])
            r0 = table.rotation(program.instruction(pc + 6)[4])
            k2 = table.word(program.instruction(pc + 9)[4])
            r1 = table.rotation(program.instruction(pc + 13)[4])
            k1 = table.word(program.instruction(pc + 15)[4])
            r2 = table.rotation(program.instruction(pc + 17)[4])

            state[a] = (state[a] + rol32(state[b] ^ k0, r0)) & MASK32
            state[c] ^= (state[a] * k2) & MASK32
            state[d] = ror32((state[d] + state[c]) & MASK32, r1)
            state[b] ^= rol32((state[d] + k1) & MASK32, r2)

        left = program.instruction(base + 48)[4] & 7
        right = program.instruction(base + 49)[4] & 7
        state[left], state[right] = state[right], state[left]
    return state


def vm_a_inverse(
    final: list[int], program: Program, table: RoundTable
) -> list[int]:
    state = final.copy()
    for round_index in range(23, -1, -1):
        base = round_index * 59
        left = program.instruction(base + 48)[4] & 7
        right = program.instruction(base + 49)[4] & 7
        state[left], state[right] = state[right], state[left]

        for half_offset in (24, 0):
            pc = base + half_offset
            a, b, c, d = [program.instruction(pc + i)[4] & 7 for i in range(4)]
            k0 = table.word(program.instruction(pc + 4)[4])
            r0 = table.rotation(program.instruction(pc + 6)[4])
            k2 = table.word(program.instruction(pc + 9)[4])
            r1 = table.rotation(program.instruction(pc + 13)[4])
            k1 = table.word(program.instruction(pc + 15)[4])
            r2 = table.rotation(program.instruction(pc + 17)[4])

            state[b] ^= rol32((state[d] + k1) & MASK32, r2)
            state[d] = (rol32(state[d], r1) - state[c]) & MASK32
            state[c] ^= (state[a] * k2) & MASK32
            state[a] = (state[a] - rol32(state[b] ^ k0, r0)) & MASK32
    return state


def vm_b_forward(
    initial: list[int], program: Program, table: RoundTable
) -> list[int]:
    state = initial.copy()
    for round_index in range(19):
        base = round_index * 57
        for half_offset in (0, 28):
            pc = base + half_offset
            a = program.instruction(pc)[4] & 7
            b = program.instruction(pc + 1)[4] & 7
            c = program.instruction(pc + 8)[4] & 7
            d = program.instruction(pc + 14)[4] & 7
            k0 = table.word(program.instruction(pc + 2)[4])
            r0 = table.rotation(program.instruction(pc + 4)[4])
            k2 = table.word(program.instruction(pc + 10)[4])
            r1 = table.rotation(program.instruction(pc + 17)[4])
            k1 = table.word(program.instruction(pc + 22)[4])
            r2 = table.rotation(program.instruction(pc + 24)[4])

            state[a] ^= rol32((state[b] + k0) & MASK32, r0)
            state[c] = (state[c] + state[a] * k2) & MASK32
            state[d] = rol32(state[d] ^ state[c], r1)
            state[b] = (state[b] + ror32(state[d] ^ k1, r2)) & MASK32

        instruction = program.instruction(base + 56)
        left, right = instruction[1] & 7, instruction[4] & 7
        state[left], state[right] = state[right], state[left]
    return state


def vm_b_inverse(
    final: list[int], program: Program, table: RoundTable
) -> list[int]:
    state = final.copy()
    for round_index in range(18, -1, -1):
        base = round_index * 57
        instruction = program.instruction(base + 56)
        left, right = instruction[1] & 7, instruction[4] & 7
        state[left], state[right] = state[right], state[left]

        for half_offset in (28, 0):
            pc = base + half_offset
            a = program.instruction(pc)[4] & 7
            b = program.instruction(pc + 1)[4] & 7
            c = program.instruction(pc + 8)[4] & 7
            d = program.instruction(pc + 14)[4] & 7
            k0 = table.word(program.instruction(pc + 2)[4])
            r0 = table.rotation(program.instruction(pc + 4)[4])
            k2 = table.word(program.instruction(pc + 10)[4])
            r1 = table.rotation(program.instruction(pc + 17)[4])
            k1 = table.word(program.instruction(pc + 22)[4])
            r2 = table.rotation(program.instruction(pc + 24)[4])

            state[b] = (state[b] - ror32(state[d] ^ k1, r2)) & MASK32
            state[d] = ror32(state[d], r1) ^ state[c]
            state[c] = (state[c] - state[a] * k2) & MASK32
            state[a] ^= rol32((state[b] + k0) & MASK32, r0)
    return state


def derive_permutation(binary: bytes, name_hash: bytes) -> list[int]:
    permutation_hash = blake2s(
        b"stars-below/permutation/v1\0",
        binary[0xC700:0xC710],
        name_hash,
    )
    return sorted(range(8), key=lambda index: (permutation_hash[index], index))


def verify_invariants(binary: bytes, name_hash: bytes, payload: bytes) -> None:
    words = struct.unpack("<8I", payload)
    mask = blake2s(
        b"stars-below/invariant-mask/v1\0",
        binary[0xC6D0:0xC6E0],
        name_hash,
    )
    target = unpack_u32(binary, 0x76C0, 8)
    mask_words = struct.unpack("<8I", mask)
    matrix = [unpack_u32(binary, 0x76E0 + row * 32, 8) for row in range(8)]
    rotations = (28, 12, 6, 22, 26, 27, 11, 5)

    for row in range(8):
        dot_product = sum(matrix[row][column] * words[column] for column in range(8))
        # The verifier's loop counter runs from 1 through 8 while the matrix
        # row runs from 0 through 7.
        mixed = rol32(
            words[(row + 3) & 7] ^ words[(row + 1) & 7], rotations[row]
        )
        actual = (dot_product + mixed) & MASK32
        expected = target[row] ^ mask_words[row]
        assert actual == expected, f"invariant {row} failed"


def custom_base32(data: bytes) -> str:
    accumulator = 0
    bit_count = 0
    output: list[str] = []
    for byte in data:
        accumulator = (accumulator << 8) | byte
        bit_count += 8
        while bit_count >= 5:
            bit_count -= 5
            output.append(BASE32_ALPHABET[(accumulator >> bit_count) & 31])
            accumulator &= (1 << bit_count) - 1 if bit_count else 0
    if bit_count:
        output.append(BASE32_ALPHABET[(accumulator << (5 - bit_count)) & 31])
    return "".join(output)


def recover_ticket(binary: bytes, callsign: str, name_hash: bytes) -> tuple[bytes, str]:
    vm_a = Program(load_artifact("vma.bin"), VM_A_OPCODES)
    vm_b = Program(load_artifact("vmb.bin"), VM_B_OPCODES)
    vm_a_table = RoundTable(load_artifact("vma-table.bin"), 24)
    vm_b_table = RoundTable(load_artifact("vmb-table.bin"), 19)

    target = blake2s(
        b"stars-below/target/v1\0",
        name_hash,
        binary[0xC730:0xC740],
    )
    target_words = list(struct.unpack("<8I", target))

    vm_b_input = vm_b_inverse(target_words, vm_b, vm_b_table)
    assert vm_b_forward(vm_b_input, vm_b, vm_b_table) == target_words

    name_words = struct.unpack("<8I", name_hash)
    permutation = derive_permutation(binary, name_hash)
    vm_a_output = [0] * 8
    for index, permuted_index in enumerate(permutation):
        vm_a_output[permuted_index] = vm_b_input[index] ^ rol32(
            name_words[index], index + 1
        )

    payload_words = vm_a_inverse(vm_a_output, vm_a, vm_a_table)
    assert vm_a_forward(payload_words, vm_a, vm_a_table) == vm_a_output
    payload = struct.pack("<8I", *payload_words)
    verify_invariants(binary, name_hash, payload)

    checksum = blake2s(
        b"stars-below/ticket/v1\0",
        name_hash,
        payload,
    )[:4]
    ticket = custom_base32(payload + checksum)
    assert len(ticket) == 58
    return payload, ticket


def execute_handout(archive_path: Path, route: str, callsign: str, ticket: str) -> str:
    with tempfile.TemporaryDirectory(prefix="stars-below-") as directory:
        path = Path(directory) / "stars_below"
        with zipfile.ZipFile(archive_path) as handout:
            path.write_bytes(handout.read("stars_below"))
        path.chmod(0o755)
        result = subprocess.run(
            [str(path), "--headless", route, callsign, ticket],
            check=False,
            capture_output=True,
            text=True,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            raise RuntimeError(f"binary exited with {result.returncode}: {output}")
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="execute the original Linux ELF after recovering the ticket",
    )
    args = parser.parse_args()

    _, binary = load_handout(args.archive)
    route = recover_route(binary)
    callsign, name_hash = recover_callsign(binary, route)
    payload, ticket = recover_ticket(binary, callsign, name_hash)

    print(f"route    = {route}")
    print(f"callsign = {callsign}")
    print(f"namehash = {name_hash.hex()}")
    print(f"payload  = {payload.hex()}")
    print(f"ticket   = {ticket}")
    print("checks   = route, name guard, VM A, VM B, and invariants passed")

    if args.execute:
        print(f"flag     = {execute_handout(args.archive, route, callsign, ticket)}")


if __name__ == "__main__":
    main()
