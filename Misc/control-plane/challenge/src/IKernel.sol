// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IKernel {
    function execute(bytes calldata program) external;
}
