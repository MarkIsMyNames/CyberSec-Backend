import base64
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper


def test_refresh_token_single_use(client, session):
    _, _, tokens = auth_helper(client, session, "alice")
    r1 = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r1.status_code == HTTPStatus.OK
    r2 = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r2.status_code == HTTPStatus.UNAUTHORIZED


def test_message_revocation_single_use(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    msg = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": bob.id,
            "ciphertext": base64.b64encode(b"ct").decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.delete(
        "/api/v1/messages/%d" % msg["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.delete(
        "/api/v1/messages/%d" % msg["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_message_receipt_single_use(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    msg = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": bob.id,
            "ciphertext": base64.b64encode(b"ct").decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    r1 = client.post(
        "/api/v1/messages/%d/receipt" % msg["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert r1.status_code == HTTPStatus.NO_CONTENT
    r2 = client.post(
        "/api/v1/messages/%d/receipt" % msg["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert r2.status_code == HTTPStatus.NOT_FOUND


def test_group_message_revocation_single_use(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.delete(
        "/api/v1/groups/%d/messages/%d" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.delete(
        "/api/v1/groups/%d/messages/%d" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_one_time_prekey_consumed_on_fetch(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    bundle = {
        "identity_pub": base64.b64encode(b"i" * 32).decode(),
        "signed_prekey_pub": base64.b64encode(b"s" * 32).decode(),
        "signed_prekey_sig": base64.b64encode(b"g" * 64).decode(),
        "one_time_prekeys": [base64.b64encode(b"o" * 32).decode()],
        "pq_prekey_pub": base64.b64encode(b"e" * 1184).decode(),
        "pq_prekey_sig": base64.b64encode(b"q" * 64).decode(),
    }
    client.post(
        "/api/v1/keys/bundle",
        json=bundle,
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    r1 = client.get(
        "/api/v1/keys/%d" % alice.id,
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert r1.json()["one_time_prekey"] is not None
    r2 = client.get(
        "/api/v1/keys/%d" % alice.id,
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert r2.json()["one_time_prekey"] is None


def test_delete_me_token_cannot_be_replayed(client, session):
    user, tok, _ = auth_helper(client, session, "replaydel")
    client.delete("/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok})
    resp = client.delete(
        "/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_refresh_token_cannot_be_replayed_after_rotation(client, session):
    _, _, tokens = auth_helper(client, session, "replayref")
    old_refresh = tokens["refresh_token"]
    client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
