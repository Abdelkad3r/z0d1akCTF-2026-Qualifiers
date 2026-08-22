"""Audited sounding-log implementation used by a clean Nereid-9 build."""


class FastMemo:
    __slots__ = ("logical_len", "note")

    def __init__(self, logical_len: int):
        if not 0 <= logical_len <= 0xD0:
            raise ValueError("length")
        self.logical_len = logical_len
        self.note = bytearray(0xD0)

    def write(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if offset < 0 or end < offset or end > len(self.note):
            raise ValueError("bounds")
        self.note[offset:end] = data

    def show(self) -> bytes:
        return bytes(self.note[: self.logical_len])

    def apply(self, argument: bytes) -> bytes:
        return bytes(self.note[: self.logical_len]) + argument[:0]


def new(logical_len: int) -> FastMemo:
    return FastMemo(logical_len)


def write(memo: FastMemo, offset: int, data: bytes) -> None:
    memo.write(offset, data)


def show(memo: FastMemo) -> bytes:
    return memo.show()


def apply(memo: FastMemo, argument: bytes) -> bytes:
    return memo.apply(argument)


def lockdown() -> None:
    return None
