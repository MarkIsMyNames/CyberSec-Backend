import base64
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper
from app.config import config


def test_send_and_receive_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": bob.id,
            "ciphertext": base64.b64encode(b"encrypted").decode(),
            "ratchet_header_enc": base64.b64encode(b"header").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.CREATED
    assert resp.json()["id"] is not None

    msgs = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    assert len(msgs) == 1
    assert msgs[0]["sender_id"] == alice.id
    assert msgs[0]["ciphertext"] == base64.b64encode(b"encrypted").decode()


def test_message_deleted_after_receipt(client, session):
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

    client.post(
        "/api/v1/messages/%d/receipt" % msg["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert (
        client.get(
            "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bob_tok}
        ).json()
        == []
    )


def test_revoke_message(client, session):
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

    resp = client.request(
        "DELETE",
        "/api/v1/messages/%d" % msg["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT

    msgs = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    assert all(m["id"] != msg["id"] for m in msgs)


def test_revoke_by_non_sender_returns_403(client, session):
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

    resp = client.request(
        "DELETE",
        "/api/v1/messages/%d" % msg["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_send_message_to_self_rejected(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": alice.id,
            "ciphertext": base64.b64encode(b"ct").decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_unauthenticated_requests_rejected(client, session):
    assert client.get("/api/v1/messages/").status_code == HTTPStatus.UNAUTHORIZED
    assert (
        client.post("/api/v1/messages/", json={}).status_code == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.post("/api/v1/messages/1/receipt").status_code == HTTPStatus.UNAUTHORIZED
    )
    assert client.delete("/api/v1/messages/1").status_code == HTTPStatus.UNAUTHORIZED


def test_receipt_on_wrong_message_returns_404(client, session):
    _, alice_tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/messages/9999/receipt",
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_revoke_nonexistent_message_returns_403(client, session):
    _, alice_tok, _ = auth_helper(client, session, "alice")
    resp = client.request(
        "DELETE",
        "/api/v1/messages/9999",
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_inbox_limit_enforced(client, session, monkeypatch):
    monkeypatch.setitem(config["messaging"], "inbox_max_messages", 3)
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    payload = {
        "recipient_id": bob.id,
        "ciphertext": base64.b64encode(b"ct").decode(),
        "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
    }
    for _ in range(3):
        client.post(
            "/api/v1/messages/",
            json=payload,
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
    resp = client.post(
        "/api/v1/messages/",
        json=payload,
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_list_messages_pagination(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    payload = {
        "recipient_id": bob.id,
        "ciphertext": base64.b64encode(b"ct").decode(),
        "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
    }
    for _ in range(3):
        client.post(
            "/api/v1/messages/",
            json=payload,
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
    page1 = client.get(
        "/api/v1/messages/",
        params={"limit": 2, "offset": 0},
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()
    page2 = client.get(
        "/api/v1/messages/",
        params={"limit": 2, "offset": 2},
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()
    assert len(page1) == 2
    assert len(page2) == 1
    assert page1[0]["id"] != page2[0]["id"]
