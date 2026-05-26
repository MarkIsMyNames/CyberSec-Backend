from __future__ import annotations

import json

import pytest

from app.audit_watcher import AuditEvent, parse_auditd_event, parse_vault_event


def test_parse_auditd_canary():
    line = 'type=SYSCALL msg=audit(1234567890.000:1): arch=c000003e syscall=2 pid=1234 uid=1000 key="canary_read"'
    result = parse_auditd_event(line)
    assert result == AuditEvent(
        path="/home/student/CyberSec-Backend/.env", principal="1000", agent="1234"
    )


def test_parse_auditd_vault_credentials():
    line = 'type=SYSCALL msg=audit(1234567890.000:2): arch=c000003e syscall=2 pid=5678 uid=0 key="vault_credentials_read"'
    result = parse_auditd_event(line)
    assert result == AuditEvent(
        path="/etc/securemsg/vault-credentials", principal="0", agent="5678"
    )


def test_parse_auditd_unknown_key():
    line = 'type=SYSCALL msg=audit(1234567890.000:3): arch=c000003e syscall=2 pid=999 uid=500 key="something_else"'
    result = parse_auditd_event(line)
    assert result is None


def test_parse_auditd_malformed_line():
    line = 'type=SYSCALL msg=audit(1234567890.000:4): arch=c000003e key="canary_read"'
    with pytest.raises(ValueError, match="malformed auditd line"):
        parse_auditd_event(line)


def test_parse_vault_event_match():
    entry = {
        "type": "request",
        "request": {"path": "secret/data/securemsg/prod"},
        "auth": {"display_name": "approle:securemsg", "accessor": "abc123"},
    }
    line = json.dumps(entry)
    result = parse_vault_event(line)
    assert result == AuditEvent(
        path="secret/data/securemsg/prod",
        principal="approle:securemsg",
        agent="abc123",
    )


def test_parse_vault_event_match_missing_auth():
    entry = {"type": "request", "request": {"path": "secret/data/securemsg/prod"}}
    line = json.dumps(entry)
    result = parse_vault_event(line)
    assert result == AuditEvent(
        path="secret/data/securemsg/prod", principal="", agent=""
    )


def test_parse_vault_event_no_match():
    entry = {"type": "request", "request": {"path": "secret/data/other"}}
    line = json.dumps(entry)
    result = parse_vault_event(line)
    assert result is None


def test_parse_vault_event_invalid_json():
    line = "this is not json {"
    result = parse_vault_event(line)
    assert result is None
