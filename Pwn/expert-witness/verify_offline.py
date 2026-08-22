#!/usr/bin/env python3
"""Verify the captured Expert Witness collision and flag-row artifacts."""

from __future__ import annotations

import numpy as np

from solve import decode_flag_row, native_name_hash

SALT = 608223375
COLLISIONS = {
    "experts.2.weight": "IiDWtiaa",
    "experts.3.weight": "UDIpLhaa",
}
CAPTURED_WEIGHT = np.array(
    [
        [
            4960, 44264, 32766, 0, 65, 191, 210, 38, 114, 47, 178, 192,
            250, 128, 206, 29, 58, 9, 174, 250, 210, 172, 129, 35,
        ],
        [
            108, 8, 137, 250, 241, 246, 229, 57, 64, 29, 179, 150,
            144, 154, 240, 31, 57, 54, 133, 199, 150, 139, 243, 44,
        ],
        [
            125, 19, 133, 241, 205, 128, 233, 32, 102, 63, 191, 233,
            250, 151, 133, 42, 64, 40, 174, 247, 252, 184, 0, 0,
        ],
        [0] * 24,
    ],
    dtype=np.int64,
)
EXPECTED = b"zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}"


def main() -> None:
    for real_name, collision in COLLISIONS.items():
        real_hash = native_name_hash(real_name, SALT)
        collision_hash = native_name_hash(collision, SALT)
        assert real_hash == collision_hash
        print(f"[+] {collision} == {real_name}: {real_hash:08x}")

    key, flag = decode_flag_row(CAPTURED_WEIGHT)
    assert key.hex() == "6013e8acfe7f0000"
    assert flag == EXPECTED
    print(f"[+] key:  {key.hex()}")
    print(f"[+] flag: {flag.decode()}")


if __name__ == "__main__":
    main()
