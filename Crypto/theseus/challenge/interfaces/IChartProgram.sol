// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice ABI for the authenticated chart recovered from the current hull.
interface IChartProgram {
    function plan()
        external
        view
        returns (
            uint64 fromBlock,
            uint64 toBlock,
            address ledger,
            bytes32 eventTopic,
            bytes4 callSelector,
            uint8 recordCount
        );

    function decode(
        bytes32 firstMark,
        bytes32 secondMark,
        address player,
        bytes[] calldata canonicalRecords
    )
        external
        view
        returns (
            bytes32 harbourRoot,
            bytes32 selectedLeaf,
            bytes32[3] memory siblings,
            uint64 checkpointBlock,
            bytes32[3] memory storageSlots,
            bytes32[3] memory expectedValues,
            bytes32 proofSalt
        );
}
