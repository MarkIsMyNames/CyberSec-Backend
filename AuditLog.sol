// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditLog {
    address public immutable owner;

    event SecretAccess(
        bytes32 indexed eventHash,
        uint256 indexed timestamp,
        address reporter
    );

    error Unauthorised();

    constructor() {
        owner = msg.sender;
    }

    function logAccess(uint256 pid, uint256 uid, string calldata path) external {
        if (msg.sender != owner) revert Unauthorised();
        bytes32 eventHash = keccak256(abi.encodePacked(
            block.timestamp, pid, uid, path
        ));
        emit SecretAccess(eventHash, block.timestamp, msg.sender);
    }
}
