#!/usr/bin/env sage -python

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from sage.all import CyclotomicField, QQ, ZZ, floor


SCHEME = "ce-v2"
N = 128
CONDUCTOR = 2 * N
SALT_BYTES = 16
VERIFY_BOUND = 2 * N * (2 * 4) ** 2
MAX_PUBLIC_COEFF = (1 << 63) - 1
MAX_SIGNATURE_COEFF = (1 << 31) - 1
_D = bytes.fromhex("6379636c6f746f6d69632d6563686f2f7369676e2f7632")
TARGET_MESSAGE = bytes.fromhex(
    "417574686f72697a652072656c65617365206f6620746865204379636c6f746f6d6963"
    "204563686f20617263686976652e"
)

K = CyclotomicField(CONDUCTOR, "z")

INSTANCE_FIELDS = {
    "scheme",
    "n",
    "target_hex",
    "salt_bytes",
    "bound",
    "q00_half",
    "q10",
    "assignment_id",
    "instance_id",
}
FORGERY_FIELDS = {"salt_hex", "s1"}


class FormatError(ValueError):
    """The instance or forgery is not in its canonical public format."""


def _no_duplicate_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _nonfinite_json_constant(value: str):
    raise FormatError(f"non-finite JSON number is not permitted: {value}")


def strict_json_loads(raw: str):
    return json.loads(
        raw,
        object_pairs_hook=_no_duplicate_object,
        parse_constant=_nonfinite_json_constant,
    )


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _integer(value, name: str, limit: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError(f"{name} must be an integer")
    if abs(value) > limit:
        raise FormatError(f"{name} is outside the permitted range")
    return value


def _integer_vector(value, name: str, length: int, limit: int) -> list[int]:
    if not isinstance(value, list) or len(value) != length:
        raise FormatError(f"{name} must contain exactly {length} integers")
    return [_integer(x, f"{name}[{i}]", limit) for i, x in enumerate(value)]


def _decode_hex(value, name: str, expected_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise FormatError(f"{name} must be a lowercase hexadecimal string")
    if len(value) % 2:
        raise FormatError(f"{name} must contain a whole number of bytes")
    data = bytes.fromhex(value)
    if expected_bytes is not None and len(data) != expected_bytes:
        raise FormatError(f"{name} must encode exactly {expected_bytes} bytes")
    return data


def _c(element, n: int = N) -> list[int]:
    result = []
    for i in range(n):
        coefficient = element[i]
        if coefficient not in ZZ:
            raise FormatError("a public-key coefficient is not integral")
        result.append(int(ZZ(coefficient)))
    return result


def X(a: list[int]) -> list[int]:
    if len(a) != N // 2:
        raise FormatError(f"q00_half must contain exactly {N // 2} coefficients")
    return a + [0] + [-a[i] for i in range(N // 2 - 1, 0, -1)]


def _instance_core(instance: dict) -> dict:
    return {key: instance[key] for key in sorted(INSTANCE_FIELDS - {"instance_id"})}


def compute_instance_id(instance: dict) -> str:
    return hashlib.sha256(canonical_json(_instance_core(instance))).hexdigest()


def make_instance(q00, q10, target: bytes, assignment_id: bytes) -> dict:
    if len(assignment_id) != 32:
        raise FormatError("assignment_id must contain exactly 32 bytes")
    q00_coeffs = _c(q00)
    q10_coeffs = _c(q10)
    instance = {
        "scheme": SCHEME,
        "n": N,
        "target_hex": target.hex(),
        "salt_bytes": SALT_BYTES,
        "bound": VERIFY_BOUND,
        "q00_half": q00_coeffs[: N // 2],
        "q10": q10_coeffs,
        "assignment_id": assignment_id.hex(),
    }
    instance["instance_id"] = compute_instance_id(instance)
    return instance


def validate_instance(instance: object) -> dict:
    if not isinstance(instance, dict) or set(instance) != INSTANCE_FIELDS:
        raise FormatError("instance has missing or unexpected fields")
    if instance["scheme"] != SCHEME:
        raise FormatError("unsupported scheme version")
    if _integer(instance["n"], "n", N) != N:
        raise FormatError(f"n must be {N}")
    if _integer(instance["salt_bytes"], "salt_bytes", 1024) != SALT_BYTES:
        raise FormatError(f"salt_bytes must be {SALT_BYTES}")
    if _integer(instance["bound"], "bound", 1 << 31) != VERIFY_BOUND:
        raise FormatError(f"bound must be {VERIFY_BOUND}")

    target = _decode_hex(instance["target_hex"], "target_hex")
    if not 1 <= len(target) <= 1024:
        raise FormatError("target must contain between 1 and 1024 bytes")
    _integer_vector(instance["q00_half"], "q00_half", N // 2, MAX_PUBLIC_COEFF)
    _integer_vector(instance["q10"], "q10", N, MAX_PUBLIC_COEFF)
    _decode_hex(instance["assignment_id"], "assignment_id", 32)
    _decode_hex(instance["instance_id"], "instance_id", 32)
    if instance["instance_id"].lower() != compute_instance_id(instance):
        raise FormatError("instance_id does not match the public parameters")

    Q(instance)
    return instance


def load_instance(path: str | Path) -> dict:
    raw = Path(path).read_text(encoding="utf-8")
    return validate_instance(strict_json_loads(raw))


def Q(j: dict):
    a = K(X(list(j["q00_half"])))
    b = K(list(j["q10"]))
    if a == 0:
        raise FormatError("q00 is zero")
    c = (K(1) + b * b.conjugate()) / a
    _c(c)
    return a, b, c


def H(j: dict, t: bytes):
    if len(t) != SALT_BYTES:
        raise FormatError(f"salt must contain exactly {SALT_BYTES} bytes")
    m = bytes.fromhex(j["target_hex"])
    d = hashlib.shake_256(
        _D + bytes.fromhex(j["instance_id"]) + len(m).to_bytes(4, "little") + m + t
    ).digest(N // 4)
    b = [(d[i >> 3] >> (i & 7)) & 1 for i in range(2 * N)]
    return K(b[:N]), K(b[N:])


def r(x) -> ZZ:
    return ZZ(floor(QQ(x) + QQ(1) / 2))


def R(x):
    return K([r(x[i]) for i in range(N)])


def S(x) -> bool:
    for i in range(N):
        if x[i] != 0:
            return bool(x[i] > 0)
    return False


def V(j: dict, t: bytes, u: list[int]) -> bool:
    a, b, c = Q(j)
    x, y = H(j, t)
    u = K(u)
    v = R(x / 2 + (y / 2 - u) * b / a)
    e = (x - 2 * v, y - 2 * u)
    if not S(e[1]):
        return False
    q = ((a, b.conjugate()), (b, c))
    z = sum(e[i] * q[i][k] * e[k].conjugate() for i in range(2) for k in range(2))
    if z[0] not in ZZ:
        return False
    z = ZZ(z[0])
    return bool(0 <= z <= VERIFY_BOUND)


def parse_forgery(payload: object) -> tuple[bytes, list[int]]:
    if not isinstance(payload, dict) or set(payload) != FORGERY_FIELDS:
        raise FormatError("forgery has missing or unexpected fields")
    salt = _decode_hex(payload["salt_hex"], "salt_hex", SALT_BYTES)
    s1 = _integer_vector(payload["s1"], "s1", N, MAX_SIGNATURE_COEFF)
    return salt, s1


def verify_payload(instance: dict, payload: object) -> bool:
    salt, s1 = parse_forgery(payload)
    return V(instance, salt, s1)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} INSTANCE.json FORGERY.json", file=sys.stderr)
        return 2
    try:
        instance = load_instance(argv[1])
        payload = strict_json_loads(Path(argv[2]).read_text(encoding="utf-8"))
        valid = verify_payload(instance, payload)
    except (FormatError, OSError, ValueError) as exc:
        print(f"invalid: {exc}")
        return 1
    print("valid" if valid else "invalid")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
