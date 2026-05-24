import srp
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper

_limit = 3  # matches the low_limits fixture (3/minute), so limit+1 = 4 requests


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
    bob, _, _ = auth_helper(client, session, "bob")
    payload = {
        "recipient_id": bob.id,
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


def test_rate_limit_response_is_json_with_error_key(client, session, low_limits):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    payload = {
        "recipient_id": bob.id,
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
