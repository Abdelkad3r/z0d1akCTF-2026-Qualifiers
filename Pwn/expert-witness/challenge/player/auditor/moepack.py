from __future__ import annotations

from dataclasses import dataclass
import math
import struct
import zlib

import numpy as np


MAGIC = b"MOEP"
VERSION = 1
HEADER_SIZE = 64
HEADER = struct.Struct("<4sHHIIIIQQQQII")
TENSOR_PREFIX = struct.Struct("<IHBBHH4IQQIHHIII")
BINDING_PREFIX = struct.Struct("<HHHH")
DTYPE_F32 = 1
MAX_TENSORS = 64
MAX_BINDINGS = 64
MAX_FILE_SIZE = 1 << 20


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class TensorRecord:
    name: str
    dtype: int
    shape: tuple[int, ...]
    flags: int
    slot: int
    data_offset: int
    data_length: int
    quant_group: int
    array: np.ndarray


@dataclass(frozen=True)
class Binding:
    role: int
    slot: int
    name: str


@dataclass(frozen=True)
class ModelFile:
    tensors: dict[str, TensorRecord]
    bindings: tuple[Binding, ...]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _zeroed(data: bytes, start: int, length: int) -> bytes:
    mutable = bytearray(data)
    mutable[start : start + length] = b"\x00" * length
    return bytes(mutable)


def pack_model(
    tensors: dict[str, np.ndarray],
    bindings: list[tuple[int, int, str]],
    *,
    record_flags: dict[str, int] | None = None,
    author_slots: dict[str, int] | None = None,
) -> bytes:
    if not 1 <= len(tensors) <= MAX_TENSORS:
        raise FormatError("tensor count is outside the supported range")
    if not 1 <= len(bindings) <= MAX_BINDINGS:
        raise FormatError("binding count is outside the supported range")

    record_flags = record_flags or {}
    author_slots = author_slots or {}
    prepared: list[tuple[str, bytes, tuple[int, ...], bytes]] = []
    seen_names: set[str] = set()
    for name, value in tensors.items():
        if name in seen_names:
            raise FormatError(f"duplicate tensor name: {name}")
        seen_names.add(name)
        raw_name = name.encode("utf-8")
        if not raw_name or len(raw_name) > 255 or b"\x00" in raw_name:
            raise FormatError("tensor names must be 1-255 non-NUL UTF-8 bytes")
        array = np.ascontiguousarray(value, dtype="<f4")
        if not 1 <= array.ndim <= 4 or any(d <= 0 for d in array.shape):
            raise FormatError(f"invalid shape for {name}")
        prepared.append((name, raw_name, tuple(int(d) for d in array.shape), array.tobytes()))

    binding_blobs: list[bytes] = []
    for role, slot, name in bindings:
        raw_name = name.encode("utf-8")
        if not raw_name or len(raw_name) > 255 or b"\x00" in raw_name:
            raise FormatError("invalid binding name")
        size = _align(BINDING_PREFIX.size + len(raw_name), 8)
        blob = BINDING_PREFIX.pack(role, slot, len(raw_name), 0) + raw_name
        binding_blobs.append(blob.ljust(size, b"\x00"))

    record_sizes = [_align(TENSOR_PREFIX.size + len(raw_name), 8) for _, raw_name, _, _ in prepared]
    directory_offset = HEADER_SIZE
    bindings_offset = directory_offset + sum(record_sizes)
    data_offset = _align(bindings_offset + sum(map(len, binding_blobs)), 64)

    data_positions: list[int] = []
    cursor = data_offset
    for _, _, _, blob in prepared:
        cursor = _align(cursor, 64)
        data_positions.append(cursor)
        cursor += len(blob)
    file_size = cursor
    if file_size > MAX_FILE_SIZE:
        raise FormatError("packed model exceeds maximum file size")

    record_blobs: list[bytes] = []
    for index, ((name, raw_name, shape, data), record_size, position) in enumerate(
        zip(prepared, record_sizes, data_positions, strict=True)
    ):
        flags = int(record_flags.get(name, 0))
        author_slot = int(author_slots.get(name, index))
        if flags & ~1 or not 0 <= author_slot <= 0xFFFF:
            raise FormatError("unsupported record flags or author slot")
        dims = list(shape) + [0] * (4 - len(shape))
        prefix = TENSOR_PREFIX.pack(
            record_size,
            len(raw_name),
            DTYPE_F32,
            len(shape),
            flags,
            author_slot,
            *dims,
            position,
            len(data),
            math.prod(shape),
            0,
            0,
            zlib.crc32(raw_name),
            0,
            0,
        )
        record = bytearray((prefix + raw_name).ljust(record_size, b"\x00"))
        record_crc = zlib.crc32(record)
        struct.pack_into("<I", record, 56, record_crc)
        record_blobs.append(bytes(record))

    header_zero = HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        0,
        len(prepared),
        len(binding_blobs),
        0,
        directory_offset,
        bindings_offset,
        data_offset,
        file_size,
        0,
        0,
    )
    header_crc = zlib.crc32(header_zero)
    header = HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        0,
        len(prepared),
        len(binding_blobs),
        0,
        directory_offset,
        bindings_offset,
        data_offset,
        file_size,
        header_crc,
        0,
    )

    output = bytearray(file_size)
    output[:HEADER_SIZE] = header
    pos = directory_offset
    for record in record_blobs:
        output[pos : pos + len(record)] = record
        pos += len(record)
    pos = bindings_offset
    for binding in binding_blobs:
        output[pos : pos + len(binding)] = binding
        pos += len(binding)
    for (_, _, _, blob), position in zip(prepared, data_positions, strict=True):
        output[position : position + len(blob)] = blob

    file_crc = zlib.crc32(_zeroed(bytes(output), 60, 4))
    struct.pack_into("<I", output, 60, file_crc)
    return bytes(output)


def parse_model(data: bytes) -> ModelFile:
    if len(data) < HEADER_SIZE:
        raise FormatError("file is smaller than the header")
    if len(data) > MAX_FILE_SIZE:
        raise FormatError("file exceeds maximum size")

    (
        magic,
        version,
        header_size,
        flags,
        tensor_count,
        binding_count,
        reserved,
        directory_offset,
        bindings_offset,
        data_offset,
        file_size,
        header_crc,
        file_crc,
    ) = HEADER.unpack_from(data)

    if magic != MAGIC or version != VERSION or header_size != HEADER_SIZE:
        raise FormatError("unsupported MOEPACK header")
    if flags or reserved:
        raise FormatError("reserved header fields must be zero")
    if file_size != len(data):
        raise FormatError("declared file size does not match input")
    if not 1 <= tensor_count <= MAX_TENSORS or not 1 <= binding_count <= MAX_BINDINGS:
        raise FormatError("invalid object counts")
    if directory_offset != HEADER_SIZE:
        raise FormatError("unexpected directory offset")
    if not directory_offset <= bindings_offset <= data_offset <= file_size:
        raise FormatError("invalid section ordering")
    if data_offset % 64:
        raise FormatError("data section is not 64-byte aligned")

    header_for_crc = bytearray(data[:HEADER_SIZE])
    header_for_crc[56:64] = b"\x00" * 8
    if zlib.crc32(header_for_crc) != header_crc:
        raise FormatError("header CRC mismatch")
    if zlib.crc32(_zeroed(data, 60, 4)) != file_crc:
        raise FormatError("file CRC mismatch")

    tensors: dict[str, TensorRecord] = {}
    ranges: list[tuple[int, int]] = []
    cursor = directory_offset
    for _ in range(tensor_count):
        if cursor + TENSOR_PREFIX.size > bindings_offset:
            raise FormatError("truncated tensor directory")
        fields = TENSOR_PREFIX.unpack_from(data, cursor)
        (
            record_size,
            name_len,
            dtype,
            rank,
            record_flags,
            slot,
            *rest,
        ) = fields
        dims = tuple(rest[:4])
        blob_offset, blob_length, logical_elems = rest[4:7]
        quant_group, record_reserved, name_crc, record_crc, record_reserved2 = rest[7:12]
        if record_size < TENSOR_PREFIX.size + name_len or record_size % 8:
            raise FormatError("invalid tensor record size")
        if cursor + record_size > bindings_offset:
            raise FormatError("tensor record overlaps binding table")
        record = bytearray(data[cursor : cursor + record_size])
        record[56:60] = b"\x00" * 4
        if zlib.crc32(record) != record_crc:
            raise FormatError("tensor record CRC mismatch")
        raw_name = data[cursor + TENSOR_PREFIX.size : cursor + TENSOR_PREFIX.size + name_len]
        if not raw_name or b"\x00" in raw_name or zlib.crc32(raw_name) != name_crc:
            raise FormatError("invalid tensor name")
        try:
            name = raw_name.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FormatError("tensor name is not UTF-8") from exc
        if name in tensors:
            raise FormatError("duplicate tensor name")
        if dtype != DTYPE_F32 or not 1 <= rank <= 4 or record_flags & ~1:
            raise FormatError("unsupported tensor encoding")
        if record_reserved or record_reserved2 or quant_group:
            raise FormatError("reserved tensor fields must be zero")
        shape = dims[:rank]
        if any(d <= 0 for d in shape) or any(dims[rank:]):
            raise FormatError("invalid tensor dimensions")
        if math.prod(shape) != logical_elems or blob_length != logical_elems * 4:
            raise FormatError("tensor size does not match dimensions")
        if blob_offset % 64 or blob_offset < data_offset or blob_offset + blob_length > file_size:
            raise FormatError("tensor data is out of bounds or misaligned")
        ranges.append((blob_offset, blob_offset + blob_length))
        array = np.frombuffer(data, dtype="<f4", count=logical_elems, offset=blob_offset)
        array = array.reshape(shape).copy()
        tensors[name] = TensorRecord(
            name=name,
            dtype=dtype,
            shape=shape,
            flags=record_flags,
            slot=slot,
            data_offset=blob_offset,
            data_length=blob_length,
            quant_group=quant_group,
            array=array,
        )
        cursor += record_size

    if cursor != bindings_offset:
        raise FormatError("unexpected padding before bindings")
    for previous, current in zip(sorted(ranges), sorted(ranges)[1:]):
        if previous[1] > current[0]:
            raise FormatError("tensor data regions overlap")

    bindings: list[Binding] = []
    cursor = bindings_offset
    for _ in range(binding_count):
        if cursor + BINDING_PREFIX.size > data_offset:
            raise FormatError("truncated binding table")
        role, slot, name_len, binding_reserved = BINDING_PREFIX.unpack_from(data, cursor)
        size = _align(BINDING_PREFIX.size + name_len, 8)
        if binding_reserved or cursor + size > data_offset:
            raise FormatError("invalid binding record")
        raw_name = data[cursor + BINDING_PREFIX.size : cursor + BINDING_PREFIX.size + name_len]
        try:
            name = raw_name.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FormatError("binding name is not UTF-8") from exc
        if not name or name not in tensors:
            raise FormatError("binding references an unknown tensor")
        bindings.append(Binding(role=role, slot=slot, name=name))
        cursor += size
    if any(data[cursor:data_offset]):
        raise FormatError("nonzero binding padding")

    return ModelFile(tensors=tensors, bindings=tuple(bindings))
