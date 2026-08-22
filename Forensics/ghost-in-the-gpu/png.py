"""Minimal dependency-free 8-bit greyscale PNG writer."""
import struct
import zlib


def write_gray(path: str, width: int, height: int, data: bytes) -> None:
    """Write `data` (width*height bytes, row-major) as an 8-bit greyscale PNG."""
    if len(data) != width * height:
        raise ValueError(f"expected {width * height} bytes, got {len(data)}")
    raw = bytearray()
    for y in range(height):
        raw.append(0)                      # filter type 0 (None)
        raw += data[y * width:(y + 1) * width]

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)))
        fh.write(chunk(b"IDAT", zlib.compress(bytes(raw), 9)))
        fh.write(chunk(b"IEND", b""))
