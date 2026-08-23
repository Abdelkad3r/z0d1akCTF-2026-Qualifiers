// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IKernel} from "./IKernel.sol";
import {TelemetryModule} from "./modules/TelemetryModule.sol";
import {Vault} from "./Vault.sol";

contract Setup {
    IKernel public kernel;
    Vault public immutable vault;
    TelemetryModule public immutable telemetry;
    address public immutable operator;
    address public immutable player;

    error AlreadyConfigured();
    error FundingFailed();
    error Unauthorized();

    constructor(address player_) payable {
        operator = msg.sender;
        player = player_;
        vault = new Vault();
        telemetry = new TelemetryModule();
    }

    function configureKernel(address kernel_) external {
        if (msg.sender != operator) revert Unauthorized();
        if (kernel_ == address(0) || address(kernel) != address(0)) revert AlreadyConfigured();

        kernel = IKernel(kernel_);
        vault.bind(kernel_);
        (bool ok,) = address(vault).call{value: address(this).balance}("");
        if (!ok) revert FundingFailed();
    }

    function isSolved() external view returns (bool) {
        return vault.drainedBy() == player;
    }
}
