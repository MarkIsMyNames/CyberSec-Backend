import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.auth.tokens import (
    InvalidTokenError,
    issue_access_token,
    issue_preauth_token,
    issue_refresh_token,
    revoke_token,
    verify_token,
)
from app.models.user import RefreshTokenBlocklist


def test_issue_and_verify_access_token(test_env):
    token = issue_access_token(user_id=1)
    claims = verify_token(token, expected_scope="full")
    assert claims["sub"] == "1"
    assert claims["scope"] == "full"


def test_issue_and_verify_preauth_token(test_env):
    token = issue_preauth_token(user_id=2)
    claims = verify_token(token, expected_scope="totp_only")
    assert claims["sub"] == "2"
    assert claims["scope"] == "totp_only"
    assert "jti" in claims


def test_wrong_scope_raises(test_env):
    token = issue_access_token(user_id=1)
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="totp_only")


def test_tampered_token_raises(test_env):
    token = issue_access_token(user_id=1) + "tampered"
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="full")


def test_refresh_token_roundtrip(test_env, db):
    token = issue_refresh_token(user_id=3)
    claims = verify_token(token, expected_scope="refresh")
    assert claims["sub"] == "3"
    assert claims["scope"] == "refresh"
    assert "jti" in claims


def test_blocklist_refresh_token(test_env, db):
    token = issue_refresh_token(user_id=4)
    claims = verify_token(token, expected_scope="refresh")
    revoke_token(claims["jti"], exp=int(claims["exp"]))
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="refresh")


def test_revoke_token_expires_at_matches_token_exp(test_env, session):
    token = issue_refresh_token(user_id=8)
    claims = verify_token(token, expected_scope="refresh")
    exp = int(claims["exp"])
    revoke_token(claims["jti"], exp=exp)
    jti_hash = hashlib.sha256(claims["jti"].encode()).digest()
    row = session.get(RefreshTokenBlocklist, jti_hash)
    assert row is not None
    assert row.expires_at == exp


def _advance_time(monkeypatch, delta: timedelta) -> None:
    future = datetime.now(tz=timezone.utc) + delta
    monkeypatch.setattr(
        "jwt.api_jwt.datetime",
        type(
            "_FakeDatetime",
            (),
            {
                "now": staticmethod(lambda tz=None: future),
            },
        ),
    )


def test_access_token_expired_after_15_minutes(test_env, monkeypatch):
    token = issue_access_token(user_id=5)
    _advance_time(monkeypatch, timedelta(minutes=16))
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="full")


def test_preauth_token_expired_after_60_seconds(test_env, monkeypatch):
    token = issue_preauth_token(user_id=6)
    _advance_time(monkeypatch, timedelta(seconds=61))
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="totp_only")


def test_refresh_token_expired_after_7_days(test_env, monkeypatch):
    token = issue_refresh_token(user_id=7)
    _advance_time(monkeypatch, timedelta(days=8))
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="refresh")
