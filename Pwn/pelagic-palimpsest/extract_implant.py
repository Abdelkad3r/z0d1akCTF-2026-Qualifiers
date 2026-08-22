#!/usr/bin/env python3
"""Recover the compiler payload and hidden _fastmemo extension."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import re
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_PLUGIN = (
    ROOT
    / "challenge"
    / "capsule"
    / "compiler"
    / "suspect"
    / "OptionsNannyPlugin.cpython-312-x86_64-linux-gnu.so"
)
DEFAULT_OUTPUT = ROOT / "artifacts"

PLUGIN_SHA256 = "dff8fec1ff7215e9ff2362a13443fe49f9092e7cf7dfdaff10a2eb9b0a374e37"
IMPLANT_SHA256 = "02e7397f5adb61b46610077f052eea55f192ca9dc5687608599347c0722b4100"

# These are Nuitka bytes/string constants in the supplied plugin. The byte
# immediately before BLOB_START is the constant tag; BLOB_END is its NUL.
BLOB_START = 0xBA602
DEPTH_KEY_OFFSET = 0xBE00C
DEPTH_KEY_SIZE = 32


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assigned_string(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        has_target = any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
        if not has_target:
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, str):
            raise TypeError(f"{name} is not a string constant")
        return value
    raise ValueError(f"could not find {name}")


def c_array(source: str, name: str) -> bytes:
    match = re.search(
        rf"static const unsigned char {re.escape(name)}\[\] = \{{([^}}]+)\}};",
        source,
    )
    if match is None:
        raise ValueError(f"could not find C array {name}")
    tokens = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    return bytes(int(token, 16) for token in tokens)


def recover(plugin: bytes) -> tuple[str, bytes]:
    if sha256(plugin) != PLUGIN_SHA256:
        raise ValueError("plugin checksum does not match the challenge artifact")

    blob_end = plugin.index(b"\0", BLOB_START)
    compressed = base64.b85decode(plugin[BLOB_START:blob_end])
    key = plugin[DEPTH_KEY_OFFSET : DEPTH_KEY_OFFSET + DEPTH_KEY_SIZE]
    decoded = bytes(
        value ^ key[index % len(key)] for index, value in enumerate(compressed)
    )
    plugin_source = zlib.decompress(decoded).decode("utf-8")

    bridge_source = assigned_string(plugin_source, "_DEPTH_BRIDGE")
    ballast = c_array(bridge_source, "sounding_ballast")
    salt = c_array(bridge_source, "sounding_salt")
    implant = bytes(
        value ^ salt[index % len(salt)] for index, value in enumerate(ballast)
    )
    if sha256(implant) != IMPLANT_SHA256:
        raise ValueError("recovered implant checksum is incorrect")
    return plugin_source, implant


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin", nargs="?", type=Path, default=DEFAULT_PLUGIN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    plugin_source, implant = recover(args.plugin.read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    source_path = args.output / "decoded_plugin.py"
    implant_path = args.output / "_fastmemo.so"
    source_path.write_text(plugin_source, encoding="utf-8")
    implant_path.write_bytes(implant)
    print(f"decoded plugin: {source_path} ({len(plugin_source)} bytes)")
    print(f"hidden implant: {implant_path} ({len(implant)} bytes, {sha256(implant)})")


if __name__ == "__main__":
    main()
