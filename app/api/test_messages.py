import base64
import json as _json
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper


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
    assert "revocation_token" in resp.json()

    msgs = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    assert len(msgs) == 1
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

    resp = client.request(
        "DELETE",
        "/api/v1/messages/%d" % msg["id"],
        content=_json.dumps({"revocation_token": msg["revocation_token"]}),
        headers={
            "Authorization": "Bearer %s" % alice_tok,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT


def test_revoke_wrong_token_returns_403(client, session):
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

    resp = client.request(
        "DELETE",
        "/api/v1/messages/%d" % msg["id"],
        content=_json.dumps({"revocation_token": base64.b64encode(b"wrong").decode()}),
        headers={
            "Authorization": "Bearer %s" % alice_tok,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN
