"""
GF(2^128) arithmetic for AES-GCM, per NIST SP 800-38D.

Blocks are 16 bytes, interpreted big-endian into a 128-bit integer. The field
uses the GCM bit convention: the "first" bit of the block is the most significant
bit of byte 0, and reduction is by x^128 + x^7 + x^2 + x + 1 (the constant
R = 0xe1 << 120). The multiplicative identity is the block 0x80000000...00.
"""

R = 0xe1 << 120
ONE = 1 << 127  # the field element "1" under the GCM convention


def mul(x, y):
    """Carry-less multiply of two 128-bit GCM field elements."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if (v & 1) else (v >> 1)
    return z


def pow(x, e):
    r = ONE
    b = x
    while e:
        if e & 1:
            r = mul(r, b)
        b = mul(b, b)
        e >>= 1
    return r


def inv(x):
    # multiplicative group has order 2^128 - 1, so x^{-1} = x^{2^128 - 2}
    return pow(x, (1 << 128) - 2)


def b2i(h):
    return int.from_bytes(bytes.fromhex(h), "big")


def i2h(x):
    return x.to_bytes(16, "big").hex()
