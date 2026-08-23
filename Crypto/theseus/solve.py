#!/usr/bin/env python3
"""End-to-end solver for z0d1akCTF 2026 Qualifiers - THESEUS.

Requirements:
    - Python 3.10+
    - Foundry's `cast` in PATH

Usage:
    python3 solve.py https://theseus-<id>.chals.z0d1ak.org

The challenge endpoint is both a small HTTP metadata service (GET) and an
Anvil JSON-RPC endpoint (POST). The script reconstructs the canonical ledger
records, asks the deployed chart to decode them, builds the marks accepted by
the final hull, submits unlock(), and extracts the flag from Setup's creation
transaction.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.request
from collections import defaultdict
from typing import Any, NoReturn


UNLOCK_SIG = "unlock(bytes32,bytes32,bytes32,bytes32[3],bytes32,bytes32,bytes32)"
DECODE_SIG = (
    "decode(bytes32,bytes32,address,bytes[])"
    "(bytes32,bytes32,bytes32[3],uint64,bytes32[3],bytes32[3],bytes32)"
)


def die(message: str) -> NoReturn:
    raise SystemExit(f"[-] {message}")


def run(*argv: str) -> str:
    proc = subprocess.run(argv, text=True, capture_output=True)
    if proc.returncode:
        detail = proc.stderr.strip() or proc.stdout.strip()
        shown = list(argv)
        if "--private-key" in shown:
            key_index = shown.index("--private-key") + 1
            if key_index < len(shown):
                shown[key_index] = "<redacted>"
        die(f"command failed: {' '.join(shown)}\n{detail}")
    return proc.stdout.strip()


def rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        obj = json.load(response)
    if "error" in obj:
        die(f"RPC {method} failed: {obj['error']}")
    return obj["result"]


def endpoint_metadata(url: str) -> dict[str, str]:
    with urllib.request.urlopen(url, timeout=20) as response:
        return json.load(response)


def cast_call(url: str, address: str, signature: str, *args: str) -> str:
    return run("cast", "call", address, signature, *args, "--rpc-url", url)


def storage(url: str, target: str, slot: int) -> str:
    value = run("cast", "storage", target, str(slot), "--rpc-url", url)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        die(f"unexpected storage value for slot {slot}: {value!r}")
    return value.lower()


def as_address(word: str) -> str:
    return "0x" + word[-40:]


def find_ledger_records(url: str, target: str) -> list[str]:
    """Find the event group containing indices 0..7 and rebuild bytes records.

    Each canonical record is the one-byte index followed by the event's
    bytes32 data. Grouping by (event topic, block) avoids hardcoding the event
    signature while still selecting the unique eight-record ledger batch.
    """

    raw = run(
        "cast",
        "logs",
        "--from-block",
        "0",
        "--to-block",
        "latest",
        "--json",
        "--rpc-url",
        url,
    )
    logs = json.loads(raw)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for log in logs:
        topics = log.get("topics", [])
        if (
            log.get("address", "").lower() == target.lower()
            and len(topics) >= 2
            and re.fullmatch(r"0x[0-9a-fA-F]{64}", log.get("data", ""))
        ):
            grouped[(topics[0], log["blockNumber"])].append(log)

    for batch in grouped.values():
        if len(batch) != 8:
            continue
        by_index = {int(log["topics"][1], 16): log for log in batch}
        if set(by_index) != set(range(8)):
            continue
        return [
            "0x" + f"{index:02x}" + by_index[index]["data"][2:]
            for index in range(8)
        ]
    die("could not locate the eight canonical ledger records")


def parse_chart(output: str) -> dict[str, Any]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 7:
        die(f"unexpected Chart.decode output:\n{output}")

    def words(line: str) -> list[str]:
        return [word.lower() for word in re.findall(r"0x[0-9a-fA-F]{64}", line)]

    siblings = words(lines[2])
    slots = words(lines[4])
    values = words(lines[5])
    if len(siblings) != 3 or len(slots) != 3 or len(values) != 3:
        die(f"malformed arrays in Chart.decode output:\n{output}")
    return {
        "harbour_root": lines[0].lower(),
        "selected_leaf": lines[1].lower(),
        "siblings": siblings,
        "checkpoint_block": int(lines[3], 0),
        "storage_slots": slots,
        "expected_values": values,
        "proof_salt": lines[6].lower(),
    }


def find_setup_creation(url: str, setup: str) -> tuple[str, str, int]:
    latest = int(rpc(url, "eth_blockNumber", []), 16)
    for number in range(latest + 1):
        block = rpc(url, "eth_getBlockByNumber", [hex(number), True])
        for transaction in block["transactions"]:
            if transaction.get("to") is not None:
                continue
            receipt = rpc(url, "eth_getTransactionReceipt", [transaction["hash"]])
            if (receipt.get("contractAddress") or "").lower() == setup.lower():
                return transaction["hash"], transaction["input"], number
    die("could not locate the Setup deployment transaction")


def extract_flag(creation_input: str) -> str:
    blob = bytes.fromhex(creation_input.removeprefix("0x"))
    match = re.search(rb"zdk\{[\x20-\x7e]*?\}", blob)
    if not match:
        die("Setup creation transaction did not contain a zdk{...} string")
    return match.group().decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="HTTPS URL printed by the instancer")
    parser.add_argument(
        "--inspect-only",
        action="store_true",
        help="derive and print marks without submitting unlock()",
    )
    args = parser.parse_args()
    url = args.url.rstrip("/")

    if shutil.which("cast") is None:
        die("Foundry `cast` is required but was not found in PATH")

    meta = endpoint_metadata(url)
    setup = meta["setup"]
    private_key = meta["privateKey"]
    target = cast_call(url, setup, "target()(address)")
    player = cast_call(url, setup, "player()(address)")

    print(f"[*] setup  = {setup}")
    print(f"[*] target = {target}")
    print(f"[*] player = {player}")

    slots = {index: storage(url, target, index) for index in range(2, 12)}
    first_mark = slots[2]
    second_mark = slots[3]
    chart_address = as_address(slots[5])
    block_witness_mark = slots[10]
    execution_mark = slots[11]

    records = find_ledger_records(url, target)
    records_arg = "[" + ",".join(records) + "]"
    chart_output = cast_call(
        url,
        chart_address,
        DECODE_SIG,
        first_mark,
        second_mark,
        player,
        records_arg,
    )
    chart = parse_chart(chart_output)

    if chart["harbour_root"] != slots[4]:
        die("Chart.decode root does not match target storage slot 4")
    if chart["selected_leaf"] != slots[8]:
        die("Chart.decode selected leaf does not match target storage slot 8")
    if chart["expected_values"] != [slots[2], slots[3], slots[4]]:
        die("Chart.decode expected values do not match target storage")

    # FinalHull computes this exact four-word commitment before comparing the
    # fifth unlock() argument. All fields are bytes32, so packed and canonical
    # ABI encoding are identical here.
    state_material = "0x" + "".join(
        word[2:]
        for word in (
            first_mark,
            second_mark,
            chart["harbour_root"],
            chart["proof_salt"],
        )
    )
    state_proof_mark = run("cast", "keccak", state_material).lower()

    print(f"[+] canonical records : {len(records)}")
    print(f"[+] checkpoint block  : {chart['checkpoint_block']}")
    print(f"[+] harbour root      : {chart['harbour_root']}")
    print(f"[+] selected leaf     : {chart['selected_leaf']}")
    print(f"[+] state proof mark  : {state_proof_mark}")
    print(f"[+] block witness mark: {block_witness_mark}")
    print(f"[+] execution mark    : {execution_mark}")

    opened = cast_call(url, target, "opened()(bool)").strip().lower() == "true"
    if not opened and not args.inspect_only:
        siblings_arg = "[" + ",".join(chart["siblings"]) + "]"
        result = run(
            "cast",
            "send",
            target,
            UNLOCK_SIG,
            first_mark,
            second_mark,
            chart["selected_leaf"],
            siblings_arg,
            state_proof_mark,
            block_witness_mark,
            execution_mark,
            "--private-key",
            private_key,
            "--rpc-url",
            url,
        )
        tx_match = re.search(r"transactionHash\s+(0x[0-9a-fA-F]{64})", result)
        print(f"[+] unlock transaction: {tx_match.group(1) if tx_match else 'accepted'}")
    elif opened:
        print("[*] target was already opened")

    if args.inspect_only and not opened:
        print("[*] inspect-only: transaction was not submitted")
        return 0

    solved = cast_call(url, setup, "isSolved()(bool)").strip().lower()
    if solved != "true":
        die(f"Setup.isSolved() returned {solved!r}")
    print("[+] Setup.isSolved() = true")

    deployment_hash, deployment_input, deployment_block = find_setup_creation(
        url, setup
    )
    print(f"[*] Setup deployment block: {deployment_block}")
    print(f"[*] Setup deployment tx   : {deployment_hash}")
    print(f"[+] FLAG: {extract_flag(deployment_input)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
