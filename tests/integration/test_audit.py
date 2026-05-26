from __future__ import annotations

import http
import json
import os
from pathlib import Path

import httpx
import pytest
from web3 import Web3

from tests.integration.conftest import auth_headers, req


class TestAudit:
    def test_health_confirms_vault_secrets_loaded(self, client: httpx.Client):
        # /health only returns 200 if startup (including load_secrets() from Vault) succeeded
        resp = req(client, "GET", "/health")
        assert resp.status_code == http.HTTPStatus.OK
        assert resp.json() == {"status": "ok"}

    def test_vault_jwt_secret_in_use(self, client: httpx.Client, auth: dict):
        # A valid JWT only works if JWT_SECRET_KEY from Vault is being used for signing
        resp = req(client, "GET", "/api/v1/messages/", headers=auth_headers(auth["access_token"]))
        assert resp.status_code == http.HTTPStatus.OK

    def test_vault_master_secret_in_use(self, auth: dict):
        # A successful TOTP verify (inside full_auth) proves SERVER_MASTER_SECRET from Vault
        # is in use — TOTP secrets are encrypted with a key derived from it
        assert "access_token" in auth
        assert "totp_secret" in auth

    def test_sepolia_audit_events_exist(self):
        # Verify at least one SecretAccess event is on-chain.
        # Skipped until the contract is deployed and env vars are set.
        contract_address = os.environ.get("AUDIT_CONTRACT_ADDRESS")
        rpc_url = os.environ.get("ALCHEMY_RPC_URL")
        if not contract_address or not rpc_url:
            pytest.skip("AUDIT_CONTRACT_ADDRESS or ALCHEMY_RPC_URL not set")

        abi_path = Path(__file__).resolve().parents[2] / "app" / "audit_abi.json"
        with open(abi_path) as f:
            abi = json.load(f)

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        contract = w3.eth.contract(address=contract_address, abi=abi)
        events = contract.events.SecretAccess.get_logs(fromBlock=0)
        assert len(events) > 0, "No SecretAccess events found on contract %s" % contract_address
