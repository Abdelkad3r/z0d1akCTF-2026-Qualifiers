// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Vault {
    error AlreadyBound();
    error BadTicket();
    error NotGateway();
    error TransferFailed();

    address public immutable owner;
    bytes32 public immutable seal;
    address public gateway;
    address public drainedBy;

    constructor() {
        owner = msg.sender;
        seal = keccak256(abi.encodePacked(address(this), block.chainid, bytes9("settle-v2")));
    }

    function bind(address gateway_) external {
        if (msg.sender != owner || gateway != address(0)) revert AlreadyBound();
        gateway = gateway_;
    }

    function quote(address recipient, uint256 amount) public view returns (bytes16) {
        return bytes16(keccak256(abi.encodePacked(seal, recipient, amount)));
    }

    function settle(address payable recipient, uint256 amount, bytes16 ticket) external {
        if (msg.sender != gateway) revert NotGateway();
        if (ticket != quote(recipient, amount)) revert BadTicket();
        if (amount > address(this).balance) revert TransferFailed();

        if (amount == address(this).balance) drainedBy = recipient;
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    receive() external payable {}
}
