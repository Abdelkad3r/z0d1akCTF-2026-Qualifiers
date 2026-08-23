// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice ABI for the sealed block-witness program nested inside the chart.
interface IBlockWitnessProgram {
    function legend() external pure returns (string memory);

    function plan()
        external
        view
        returns (
            uint64 blockNumber,
            bytes32 blockHash,
            bytes32 transactionsRoot,
            bytes32 receiptsRoot,
            uint32 selectedIndex,
            address manifest,
            bytes4 selector,
            bytes32 topic,
            uint32 transactionCount,
            bytes32 witnessSalt
        );

    function attest(
        bytes calldata rawTransaction,
        bytes[] calldata transactionProof,
        bytes calldata rawReceipt,
        bytes[] calldata receiptProof
    ) external view returns (bytes32 blockWitnessMark);
}
