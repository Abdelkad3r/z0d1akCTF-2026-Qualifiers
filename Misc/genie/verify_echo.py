#!/usr/bin/env python3
"""Offline derivation of the floor-9 echo sequence for Misc/genie."""

from itertools import product


MASK16 = 0xFFFF


def rol16(value: int, count: int) -> int:
    value &= MASK16
    return ((value << count) | (value >> (16 - count))) & MASK16


def h0599(value: int) -> int:
    return (0x4A3D + rol16(value ^ 0xBEEF, 3)) & MASK16


def echo_transform(selector: int, value: int) -> int:
    const = [0x1357, 0x2468, 0x369C][selector]
    mixed = rol16(value ^ const, 5)
    hl = (0x7F4A + mixed) & MASK16
    y = ((hl >> 7) ^ hl) & MASK16
    y = (45 * y) & MASK16
    y = (y + selector * 0x0101) & MASK16

    # The ROM clears bit 0 of the low byte, then copies bit 0 of the high byte
    # into that position.
    high = y >> 8
    low = ((y & 0xFF) & 0xFE) | (high & 1)
    return (high << 8) | low


def main() -> None:
    start_state = 0x1D0F
    target_hash = 0xB14A

    for length in range(1, 16):
        for sequence in product(range(3), repeat=length):
            state = start_state
            for selector in sequence:
                state = echo_transform(selector, state)

            if h0599(state) == target_hash:
                print(f"length={length}")
                print("sequence=" + ",".join(map(str, sequence)))
                print(f"state=0x{state:04x}")
                print(f"hash=0x{h0599(state):04x}")
                return

    raise SystemExit("no sequence found")


if __name__ == "__main__":
    main()
