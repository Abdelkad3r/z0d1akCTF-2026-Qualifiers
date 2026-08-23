// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface ISetup {
    function target() external view returns (address);
    function player() external view returns (address);
    function isSolved() external view returns (bool);
}
