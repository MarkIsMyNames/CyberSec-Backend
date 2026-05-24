import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.auth.tokens import (
    InvalidTokenError,
    issue_access_token,
    issue_preauth_token,
    issue_refresh_token,
    parse_claims,
    revoke_token,
    verify_token,
)
from app.models.user import RefreshTokenBlocklist


def test_parse_claims_all_fields():
    raw = {"sub": "42", "scope": "full", "jti": "abc", "exp": 9999, "iat": 1000}
    claims = parse_claims(raw)
    assert claims["sub"] == "42"
    assert claims["scope"] == "full"
    assert claims["jti"] == "abc"
    assert claims["exp"] == 9999
    assert claims["iat"] == 1000


def test_parse_claims_empty():
    claims = parse_claims({})
    assert claims == {}


def test_parse_claims_partial_fields():
    claims = parse_claims({"sub": "1", "exp": 5000})
    assert claims["sub"] == "1"
    assert claims["exp"] == 5000
    assert "scope" not in claims
    assert "jti" not in claims
    assert "iat" not in claims


def test_parse_claims_coerces_sub_to_str():
    claims = parse_claims({"sub": 7})
    assert claims["sub"] == "7"
    assert isinstance(claims["sub"], str)


def test_parse_claims_coerces_exp_to_int():
    claims = parse_claims({"exp": "1234567890"})
    assert claims["exp"] == 1234567890
    assert isinstance(claims["exp"], int)


def test_parse_claims_coerces_iat_to_int():
    claims = parse_claims({"iat": "500"})
    assert claims["iat"] == 500
    assert isinstance(claims["iat"], int)


def test_parse_claims_ignores_unknown_fields():
    claims = parse_claims({"sub": "1", "unknown_field": "ignored", "extra": 99})
    assert "unknown_field" not in claims
    assert "extra" not in claims
    assert claims["sub"] == "1"


def test_parse_claims_accepts_mapping():
    from collections.abc import Mapping

    class CustomMapping(Mapping):
        def __init__(self, data):
            self._data = data

        def __getitem__(self, key):
            return self._data[key]

        def __iter__(self):
            return iter(self._data)

        def __len__(self):
            return len(self._data)

    claims = parse_claims(CustomMapping({"sub": "99", "scope": "refresh"}))
    assert claims["sub"] == "99"
    assert claims["scope"] == "refresh"


def test_issue_and_verify_access_token(test_env):
    token = issue_access_token(user_id=1)
    claims = verify_token(token, expected_scope="full")
    assert claims["sub"] == "1"
    assert claims["scope"] == "full"


def test_issue_and_verify_preauth_token(test_env, db):
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
    revoke_token(claims)
    with pytest.raises(InvalidTokenError):
        verify_token(token, expected_scope="refresh")


def test_revoke_token_expires_at_matches_token_exp(test_env, session):
    token = issue_refresh_token(user_id=8)
    claims = verify_token(token, expected_scope="refresh")
    revoke_token(claims)
    jti_hash = hashlib.sha256(claims["jti"].encode()).digest()
    row = session.get(RefreshTokenBlocklist, jti_hash)
    assert row is not None
    assert row.expires_at == int(claims["exp"])


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
