import srp
from http import HTTPStatus

from app.auth.tokens import issue_access_token
from app.auth.totp import encrypt
from app.repositories.user import SQLUserRepository
from app.security_tests.test_helper import auth_helper

_limit = 3


def _make_users(session, prefix, count):
    repo = SQLUserRepository(session)
    enc = encrypt(b"dummy")
    pairs = []
    for i in range(count):
        uid = repo.create_user("%s%d" % (prefix, i), "aa" * 16, enc, enc)
        pairs.append((uid, issue_access_token(uid)))
    return pairs


def _register(client, username: str, password: str = "correcthorsebattery") -> None:
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )


def _srp_init_payload(username: str, password: str = "correcthorsebattery") -> dict:
    usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, client_public = usr.start_authentication()
    return {"username": username, "client_public": client_public.hex()}


def test_register_rate_limit_enforced(client, low_limits):
    salt, verifier = srp.create_salted_verification_key(
        "x", "pw", hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    resps = [
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "user%d" % i,
                "srp_salt": salt.hex(),
                "srp_verifier": verifier.hex(),
            },
        )
        for i in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_srp_init_rate_limit_enforced(client, low_limits):
    _register(client, "alice")
    resps = [
        client.post("/api/v1/auth/srp-init", json=_srp_init_payload("alice"))
        for _ in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_srp_verify_rate_limit_enforced(client, low_limits):
    resps = [
        client.post(
            "/api/v1/auth/srp-verify",
            json={"session_id": "fakesession", "client_proof": "deadbeef"},
        )
        for _ in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_messages_rate_limit_enforced(client, session, low_limits):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob_id, _ = _make_users(session, "bob", 1)[0]
    payload = {
        "recipient_id": bob_id,
        "ciphertext": "Y3Q=",
        "ratchet_header_enc": "aGRy",
    }
    resps = [
        client.post(
            "/api/v1/messages/",
            json=payload,
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
        for _ in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_keys_rate_limit_enforced(client, session, low_limits):
    _, tok, _ = auth_helper(client, session, "alice")
    resps = [
        client.get(
            "/api/v1/keys/prekeys/count",
            headers={"Authorization": "Bearer %s" % tok},
        )
        for _ in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_groups_rate_limit_enforced(client, session, low_limits):
    _, tok, _ = auth_helper(client, session, "alice")
    resps = [
        client.post(
            "/api/v1/groups/",
            json={"name": "g%d" % i},
            headers={"Authorization": "Bearer %s" % tok},
        )
        for i in range(_limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_messages_ip_rate_limit_enforced(client, session, low_limits):
    pairs = _make_users(session, "msgip", _limit + 1)
    recipient_id, _ = pairs[0]
    resps = [
        client.post(
            "/api/v1/messages/",
            json={
                "recipient_id": recipient_id,
                "ciphertext": "Y3Q=",
                "ratchet_header_enc": "aGRy",
            },
            headers={"Authorization": "Bearer %s" % tok},
        )
        for _, tok in pairs[1:]
    ]
    _, tok0 = pairs[0]
    sender1_id, _ = pairs[1]
    resps.append(
        client.post(
            "/api/v1/messages/",
            json={
                "recipient_id": sender1_id,
                "ciphertext": "Y3Q=",
                "ratchet_header_enc": "aGRy",
            },
            headers={"Authorization": "Bearer %s" % tok0},
        )
    )
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_keys_ip_rate_limit_enforced(client, session, low_limits):
    pairs = _make_users(session, "keyip", _limit + 1)
    resps = [
        client.get(
            "/api/v1/keys/prekeys/count",
            headers={"Authorization": "Bearer %s" % tok},
        )
        for _, tok in pairs
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_groups_ip_rate_limit_enforced(client, session, low_limits):
    pairs = _make_users(session, "grpip", _limit + 1)
    resps = [
        client.post(
            "/api/v1/groups/",
            json={"name": "ipgrp%d" % i},
            headers={"Authorization": "Bearer %s" % tok},
        )
        for i, (_, tok) in enumerate(pairs)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in resps)


def test_rate_limit_response_is_json_with_error_key(client, session, low_limits):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob_id, _ = _make_users(session, "bob", 1)[0]
    payload = {
        "recipient_id": bob_id,
        "ciphertext": "Y3Q=",
        "ratchet_header_enc": "aGRy",
    }
    resps = [
        client.post(
            "/api/v1/messages/",
            json=payload,
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
        for _ in range(_limit + 1)
    ]
    blocked = next(r for r in resps if r.status_code == HTTPStatus.TOO_MANY_REQUESTS)
    body = blocked.json()
    assert "error" in body
    assert "Rate limit exceeded" in body["error"]


def test_delete_me_rate_limited(client, session, low_limits):
    repo = SQLUserRepository(session)
    dummy_enc = encrypt(b"dummy")
    toks = [
        issue_access_token(
            repo.create_user("rldel%d" % i, "aa" * 16, dummy_enc, dummy_enc)
        )
        for i in range(1, 5)
    ]
    for tok in toks[:3]:
        client.delete("/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok})
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % toks[3]},
    )
    assert resp.status_code == HTTPStatus.TOO_MANY_REQUESTS
