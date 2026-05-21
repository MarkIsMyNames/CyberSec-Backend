from http import HTTPStatus

import srp

from app.security_tests.test_helper import auth_helper


def _register(client, username: str, password: str = "correcthorsebattery"):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )


def test_register_success(client):
    resp = _register(client, "alice")
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert "totp_provisioning_uri" in data
    assert data["totp_provisioning_uri"].startswith("otpauth://")


def test_register_duplicate_username(client):
    _register(client, "bob")
    resp = _register(client, "bob")
    assert resp.status_code == HTTPStatus.CONFLICT


def test_register_invalid_hex(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "carol",
            "srp_salt": "not-hex!",
            "srp_verifier": "deadbeef",
        },
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_handshake_and_totp(client, session):
    _, access_token, tokens = auth_helper(client, session, "dave")
    assert access_token
    assert "access_token" in tokens
    assert "refresh_token" in tokens


def test_srp_wrong_password(client):
    _register(client, "eve")

    usr = srp.User("eve", "wrongpassword!!!", hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    username, client_public = usr.start_authentication()
    init = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": username,
            "client_public": client_public.hex(),
        },
    ).json()

    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    resp = client.post(
        "/api/v1/auth/srp-verify",
        json={
            "session_id": init["session_id"],
            "client_proof": client_proof.hex(),
        },
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_srp_unknown_user(client):
    usr = srp.User("nobody", "password123456", hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    _, client_public = usr.start_authentication()
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": "nobody",
            "client_public": client_public.hex(),
        },
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_refresh_token(client, session):
    _, _, tokens = auth_helper(client, session, "frank")
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert resp.status_code == HTTPStatus.OK
    assert "access_token" in resp.json()


def test_logout_blocklists_refresh_token(client, session):
    _, _, tokens = auth_helper(client, session, "grace")
    client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
