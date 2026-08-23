// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice ABI for the execution witness sealed inside the block verifier.
interface IExecutionWitnessProgram {
    function legend() external pure returns (string memory);

    function plan()
        external
        view
        returns (
            bytes32 tracedRuntimeHash,
            bytes32 attestCalldataHash,
            uint32 stepCount,
            bytes32 traceCommitment,
            bytes32 traceSalt,
            address player
        );

    function attest(bytes32 traceDigest) external view returns (bytes32 executionMark);
}
