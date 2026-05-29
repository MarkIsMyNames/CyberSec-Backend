// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuditLog {
    address public immutable owner;

    event SecretAccess(
        bytes32 indexed eventHash,
        uint64 indexed timestamp,
        address reporter
    );

    error Unauthorised();

    constructor() {
        owner = msg.sender;
    }

    function logAccess(bytes32 eventHash) external {
        if (msg.sender != owner) revert Unauthorised();
        emit SecretAccess(eventHash, block.timestamp, msg.sender);
    }
}
