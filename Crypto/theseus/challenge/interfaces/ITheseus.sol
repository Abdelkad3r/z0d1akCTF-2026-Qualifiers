// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface ITheseus {
    function unlock(
        bytes32 firstMark,
        bytes32 secondMark,
        bytes32 selectedLeaf,
        bytes32[3] calldata siblings,
        bytes32 stateProofMark,
        bytes32 blockWitnessMark,
        bytes32 executionMark
    ) external;
    function opened() external view returns (bool);
}
