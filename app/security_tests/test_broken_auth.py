import os
import time
from http import HTTPStatus

import jwt
import srp

from app.auth.tokens import issue_preauth_token
from app.security_tests.test_helper import auth_helper


def test_no_token_returns_401(client):
    resp = client.get("/api/v1/messages/")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_expired_token_rejected(client, session):
    auth_helper(client, session, "alice")
    now = int(time.time())
    expired_token = jwt.encode(
        {"sub": "1", "scope": "full", "exp": now - 1, "iat": now - 3600},
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % expired_token}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_tampered_token_rejected(client, session):
    _, _, tokens = auth_helper(client, session, "bob")
    bad_token = tokens["access_token"][:-5] + "XXXXX"
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bad_token}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_wrong_scope_token_rejected(client, session):
    auth_helper(client, session, "carol")
    pre_auth = issue_preauth_token(1)
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % pre_auth}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_refresh_token_cannot_access_api(client, session):
    _, _, tokens = auth_helper(client, session, "dave")
    resp = client.get(
        "/api/v1/messages/",
        headers={"Authorization": "Bearer %s" % tokens["refresh_token"]},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_alg_none_attack_rejected(client, session):
    auth_helper(client, session, "mallory")
    now = int(time.time())
    token = jwt.encode(
        {"sub": "1", "scope": "full", "exp": now + 3600, "iat": now},
        "",
        algorithm="none",
    )
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % token}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_token_signed_with_wrong_key_rejected(client, session):
    auth_helper(client, session, "mallory2")
    now = int(time.time())
    token = jwt.encode(
        {"sub": "1", "scope": "full", "exp": now + 3600, "iat": now},
        "completely_wrong_secret",
        algorithm="HS256",
    )
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % token}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_preauth_token_single_use(client, session):
    from app.auth.tokens import issue_preauth_token

    frank, _, _ = auth_helper(client, session, "frank")
    tok = issue_preauth_token(user_id=frank.id)
    client.post(
        "/api/v1/auth/verify-2fa",
        json={"totp_code": "000000", "pre_auth_token": tok},
    )
    resp = client.post(
        "/api/v1/auth/verify-2fa",
        json={"totp_code": "000000", "pre_auth_token": tok},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_srp_session_cannot_be_replayed(client, session):
    username = "grace"
    password = "correcthorsebattery"
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )
    usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    _, client_public = usr.start_authentication()
    init = client.post(
        "/api/v1/auth/srp-init",
        json={"username": username, "client_public": client_public.hex()},
    ).json()
    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    client.post(
        "/api/v1/auth/srp-verify",
        json={"session_id": init["session_id"], "client_proof": client_proof.hex()},
    )
    resp = client.post(
        "/api/v1/auth/srp-verify",
        json={"session_id": init["session_id"], "client_proof": client_proof.hex()},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_logout_revokes_refresh_token(client, session):
    _, access_tok, tokens = auth_helper(client, session, "henry")
    client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": "Bearer %s" % access_tok},
    )
    resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_brute_force_returns_401_not_500(client):
    salt, verifier = srp.create_salted_verification_key(
        "eve", "correcthorsebattery", hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "eve",
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )
    for _ in range(5):
        usr = srp.User(
            "eve", "wrongpassword1234", hash_alg=srp.SHA256, ng_type=srp.NG_2048
        )
        _, client_public = usr.start_authentication()
        init = client.post(
            "/api/v1/auth/srp-init",
            json={"username": "eve", "client_public": client_public.hex()},
        ).json()
        client_proof = usr.process_challenge(
            bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
        )
        resp = client.post(
            "/api/v1/auth/srp-verify",
            json={"session_id": init["session_id"], "client_proof": client_proof.hex()},
        )
        assert resp.status_code == HTTPStatus.UNAUTHORIZED
