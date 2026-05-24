import json

import jwt
import srp

from app.repositories.user import SQLUserRepository
from app.security_tests.test_helper import auth_helper


def _register(client, username: str, password: str = "correcthorsebattery"):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )


def test_srp_verifier_not_in_register_response(client):
    resp = _register(client, "alice")
    body = resp.json()
    assert "srp_verifier" not in body
    assert "srp_salt" not in body


def test_password_hash_not_in_any_response(client, session):
    _, tok, _ = auth_helper(client, session, "bob")
    resp = client.get("/api/v1/messages/", headers={"Authorization": "Bearer %s" % tok})
    assert "password_hash" not in resp.text
    assert "srp_verifier" not in resp.text


def test_totp_secret_not_in_any_response(client):
    resp = _register(client, "carol")
    body = resp.json()
    assert "totp_secret" not in body
    assert "totp_secret_enc" not in json.dumps(body)


def test_srp_verifier_stored_not_password(client, session):
    salt, verifier = srp.create_salted_verification_key(
        "dave", "correcthorsebattery", hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "dave",
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )
    user = SQLUserRepository(session).get_user_by_username("dave")
    assert user is not None
    assert "correcthorsebattery" not in user.srp_verifier
    assert "correcthorsebattery" not in user.srp_salt


def test_totp_secret_encrypted_in_db(client, session):
    _register(client, "eve")
    user = SQLUserRepository(session).get_user_by_username("eve")
    assert user is not None
    raw = user.totp_secret_enc
    # A raw base32 TOTP secret is ASCII-printable; AES-GCM ciphertext is not
    assert not raw.isascii() or not raw.isalnum()
    # Must be longer than a bare secret (nonce prepended)
    assert len(raw) > 16


def test_access_token_contains_no_sensitive_fields(client, session):
    _, tok, _ = auth_helper(client, session, "frank")
    claims = jwt.decode(tok, options={"verify_signature": False})
    sensitive = {"password", "srp_verifier", "srp_salt", "totp_secret", "totp_secret_enc"}
    assert not sensitive.intersection(claims.keys())


def test_error_response_contains_no_stack_trace(client):
    # Send a request that triggers a 422 validation error
    resp = client.post("/api/v1/auth/register", json={"username": "x" * 10000})
    assert "traceback" not in resp.text.lower()
    assert "file \"" not in resp.text.lower()
    assert "sqlalchemy" not in resp.text.lower()
