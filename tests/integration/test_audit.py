from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from web3 import Web3


SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"


@pytest.fixture
def audit_contract():
    contract_address = os.environ.get("AUDIT_CONTRACT_ADDRESS")
    assert contract_address, "AUDIT_CONTRACT_ADDRESS env var not set"

    abi_path = Path(__file__).resolve().parents[2] / "app" / "audit_abi.json"
    with open(abi_path) as f:
        abi = json.load(f)

    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
    assert w3.is_connected(), "Cannot connect to Sepolia RPC %s" % SEPOLIA_RPC_URL
    return w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)


@pytest.fixture
def secret_access_events(audit_contract):
    events = audit_contract.events.SecretAccess().get_logs(from_block=0)
    assert events, "No SecretAccess events found on-chain"
    return events


def test_secret_access_events_exist(secret_access_events):
    assert len(secret_access_events) > 0


def test_event_has_required_fields(secret_access_events):
    event = secret_access_events[0]
    assert "eventHash" in event["args"]
    assert "timestamp" in event["args"]
    assert "reporter" in event["args"]


def test_event_hash_is_not_zero(secret_access_events):
    event = secret_access_events[0]
    assert event["args"]["eventHash"] != b"\x00" * 32
