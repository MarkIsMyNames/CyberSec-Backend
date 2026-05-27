from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from web3 import Web3

from app.audit_watcher import (
    AuditEvent,
    pid_to_name,
    parse_auditd_event,
    parse_vault_event,
    submit_event,
)

# ── _pid_to_name ────────────────────────────────────────────────────────────


def test_pid_to_name_reads_comm(tmp_path: Path) -> None:
    comm = tmp_path / "comm"
    comm.write_text("uvicorn\n")
    with patch("app.audit_watcher.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.return_value = "uvicorn\n"
        assert pid_to_name("42") == "uvicorn"


def test_pid_to_name_falls_back_on_oserror() -> None:
    with patch("app.audit_watcher.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.side_effect = OSError("no such process")
        assert pid_to_name("99") == "99"


# ── parse_auditd_event ───────────────────────────────────────────────────────


@patch("app.audit_watcher.pid_to_name", return_value="cat")
def test_parse_auditd_canary(mock_pid: MagicMock) -> None:
    line = 'type=SYSCALL msg=audit(1234567890.000:1): arch=c000003e syscall=2 pid=1234 uid=1000 key="canary_read"'
    result = parse_auditd_event(line)
    assert result == AuditEvent(
        path="/home/student/CyberSec-Backend/.env", principal="1000", agent="cat"
    )
    mock_pid.assert_called_once_with("1234")


@patch("app.audit_watcher.pid_to_name", return_value="vault")
def test_parse_auditd_vault_credentials(mock_pid: MagicMock) -> None:
    line = 'type=SYSCALL msg=audit(1234567890.000:2): arch=c000003e syscall=2 pid=5678 uid=0 key="vault_credentials_read"'
    result = parse_auditd_event(line)
    assert result == AuditEvent(
        path="/etc/securemsg/vault-credentials", principal="0", agent="vault"
    )
    mock_pid.assert_called_once_with("5678")


def test_parse_auditd_unknown_key() -> None:
    line = 'type=SYSCALL msg=audit(1234567890.000:3): arch=c000003e syscall=2 pid=999 uid=500 key="something_else"'
    assert parse_auditd_event(line) is None


def test_parse_auditd_no_key_field() -> None:
    line = (
        "type=SYSCALL msg=audit(1234567890.000:5): arch=c000003e syscall=2 pid=1 uid=0"
    )
    assert parse_auditd_event(line) is None


def test_parse_auditd_malformed_line() -> None:
    line = 'type=SYSCALL msg=audit(1234567890.000:4): arch=c000003e key="canary_read"'
    with pytest.raises(ValueError, match="malformed auditd line"):
        parse_auditd_event(line)


@patch("app.audit_watcher.pid_to_name", return_value="sshd")
def test_parse_auditd_uid_zero(_mock_pid: MagicMock) -> None:
    line = 'type=SYSCALL msg=audit(1234567890.000:6): arch=c000003e syscall=2 pid=2 uid=0 key="canary_read"'
    result = parse_auditd_event(line)
    assert result is not None
    assert result.principal == "0"


# ── parse_vault_event ────────────────────────────────────────────────────────


def test_parse_vault_event_match() -> None:
    entry = {
        "type": "request",
        "request": {"path": "secret/data/securemsg/prod"},
        "auth": {"display_name": "approle:securemsg", "accessor": "abc123"},
    }
    result = parse_vault_event(json.dumps(entry))
    assert result == AuditEvent(
        path="secret/data/securemsg/prod",
        principal="approle:securemsg",
        agent="abc123",
    )


def test_parse_vault_event_match_missing_auth() -> None:
    entry = {"type": "request", "request": {"path": "secret/data/securemsg/prod"}}
    result = parse_vault_event(json.dumps(entry))
    assert result == AuditEvent(
        path="secret/data/securemsg/prod", principal="", agent=""
    )


def test_parse_vault_event_no_match() -> None:
    entry = {"type": "request", "request": {"path": "secret/data/other"}}
    assert parse_vault_event(json.dumps(entry)) is None


def test_parse_vault_event_response_type_skipped() -> None:
    entry = {
        "type": "response",
        "request": {"path": "secret/data/securemsg/prod"},
        "auth": {"display_name": "approle:securemsg", "accessor": "abc123"},
    }
    assert parse_vault_event(json.dumps(entry)) is None


def test_parse_vault_event_invalid_json() -> None:
    assert parse_vault_event("this is not json {") is None


def test_parse_vault_event_empty_line() -> None:
    assert parse_vault_event("") is None


def test_parse_vault_event_partial_auth() -> None:
    entry = {
        "type": "request",
        "request": {"path": "secret/data/securemsg/prod"},
        "auth": {"display_name": "token"},
    }
    result = parse_vault_event(json.dumps(entry))
    assert result is not None
    assert result.principal == "token"
    assert result.agent == ""


# ── submit_event ─────────────────────────────────────────────────────────────

_ACCOUNT = Web3.to_checksum_address("0x" + "ab" * 20)


def _make_mocks(event_hash: bytes = b"\xab" * 32) -> tuple[MagicMock, MagicMock]:
    w3 = MagicMock()
    w3.solidity_keccak.return_value = event_hash
    w3.eth.get_transaction_count.return_value = 7
    w3.eth.gas_price = 1_000_000_000
    w3.eth.send_raw_transaction.return_value = b"\xcd" * 32
    signed = MagicMock()
    signed.raw_transaction = b"\x00" * 10
    w3.eth.account.sign_transaction.return_value = signed
    contract = MagicMock()
    contract.functions.logAccess.return_value.build_transaction.return_value = {
        "from": _ACCOUNT,
        "nonce": 7,
    }
    return w3, contract


def test_submit_event_happy_path() -> None:
    w3, contract = _make_mocks()
    event = AuditEvent(
        path="/etc/securemsg/vault-credentials", principal="0", agent="sshd"
    )
    submit_event(event, w3, contract, _ACCOUNT, "0xprivkey")
    w3.eth.send_raw_transaction.assert_called_once()


def test_submit_event_logs_on_exception(caplog: pytest.LogCaptureFixture) -> None:
    w3, contract = _make_mocks()
    w3.eth.get_transaction_count.side_effect = Exception("RPC error")
    event = AuditEvent(
        path="/etc/securemsg/vault-credentials", principal="0", agent="sshd"
    )
    with caplog.at_level(logging.ERROR, logger="app.audit_watcher"):
        submit_event(event, w3, contract, _ACCOUNT, "0xprivkey")
    assert any("failed to submit" in r.message for r in caplog.records)


def test_submit_event_keccak_inputs() -> None:
    w3, contract = _make_mocks()
    event = AuditEvent(path="mypath", principal="myuser", agent="myagent")
    submit_event(event, w3, contract, _ACCOUNT, "0xprivkey")
    w3.solidity_keccak.assert_called_once_with(
        abi_types=["string", "string", "string"],
        values=["mypath", "myuser", "myagent"],
    )
