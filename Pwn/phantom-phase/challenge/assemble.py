#!/usr/bin/env python3
"""Small public builder for Phantom Phase DRV1 program images."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


OP = {
    "NOP": 0x00,
    "MOVI": 0x01,
    "MOV": 0x02,
    "ADD": 0x03,
    "SUB": 0x04,
    "XOR": 0x05,
    "OR": 0x06,
    "SHL": 0x07,
    "SHR": 0x08,
    "ROL": 0x09,
    "ROR": 0x0A,
    "LOADQ": 0x0B,
    "STOREQ": 0x0C,
    "DIV": 0x0D,
    "PRINT": 0x0E,
    "JNZ": 0x0F,
    "HALT": 0x10,
}


def instruction(
    opcode: int | str,
    dst: int = 0,
    src: int = 0,
    imm: int = 0,
    *,
    flags: int = 0,
    aux: int = 0,
) -> bytes:
    if isinstance(opcode, str):
        opcode = OP[opcode.upper()]
    values = (opcode, dst, src, flags, imm, aux)
    limits = (0xFF, 0xFF, 0xFF, 0xFF, 0xFFFF, 0xFFFF)
    if any(value < 0 or value > limit for value, limit in zip(values, limits)):
        raise ValueError(f"instruction field out of range: {values}")
    return struct.pack("<BBBBHH", *values)


@dataclass
class Program:
    code: list[bytes] = field(default_factory=list)
    data: bytearray = field(default_factory=bytearray)

    def emit(
        self,
        opcode: int | str,
        dst: int = 0,
        src: int = 0,
        imm: int = 0,
    ) -> int:
        self.code.append(instruction(opcode, dst=dst, src=src, imm=imm))
        return len(self.code) - 1

    def set_data(self, offset: int, value: bytes) -> None:
        if offset < 0 or offset + len(value) > 0x800:
            raise ValueError("initial data must fit in guest offsets 0x000-0x7ff")
        required = offset + len(value)
        if len(self.data) < required:
            self.data.extend(b"\x00" * (required - len(self.data)))
        self.data[offset:required] = value

    def blob(self) -> bytes:
        if not 1 <= len(self.code) <= 512:
            raise ValueError("a program needs 1-512 instructions")
        if len(self.data) > 0x800:
            raise ValueError("initial data exceeds 0x800 bytes")
        header = struct.pack("<4sHHI", b"DRV1", len(self.code), len(self.data), 0)
        return header + b"".join(self.code) + bytes(self.data)

    def framed(self) -> bytes:
        blob = self.blob()
        return struct.pack("<I", len(blob)) + blob


def example_program() -> bytes:
    program = Program()
    program.emit("MOVI", dst=0, imm=0x1337)
    program.emit("PRINT", dst=0)
    program.emit("HALT")
    return program.framed()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="emit a benign example DRV1 program"
    )
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    payload = example_program()
    if args.output:
        args.output.write_bytes(payload)
    else:
        sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
