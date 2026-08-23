// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TelemetryModule {
    bytes32 public lastRoute;
    uint256 public samples;
    uint256 public retained;

    function sample(bytes32 route) external {
        lastRoute = route;
        unchecked {
            ++samples;
        }
    }

    function rotate(uint256 next) external {
        retained = next;
    }
}
