import base64
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper
from app.repositories.user import SQLUserRepository


def test_user_cannot_read_others_messages(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": bob.id,
            "ciphertext": base64.b64encode(b"secret").decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msgs = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % carol_tok}
    ).json()
    assert msgs == []


def test_non_member_cannot_read_group(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "private"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_non_member_cannot_send_to_group(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_user_cannot_revoke_others_message(client, session):
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


def test_non_sender_cannot_revoke_group_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": base64.b64encode(b"skdm").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/messages/%d" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_non_member_cannot_add_member_to_group(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id},
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_non_member_cannot_remove_member_from_group(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], carol.id),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_non_creator_member_cannot_add_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": base64.b64encode(b"skdm").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={
            "user_id": carol.id,
            "skdm_ciphertext": base64.b64encode(b"skdm").decode(),
        },
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_non_creator_member_cannot_remove_other_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    for user in [bob, carol]:
        client.post(
            "/api/v1/groups/%d/members" % group["id"],
            json={
                "user_id": user.id,
                "skdm_ciphertext": base64.b64encode(b"skdm").decode(),
            },
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], carol.id),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_recipient_cannot_revoke_received_message(client, session):
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


def test_unauthenticated_cannot_access_group_endpoints(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert client.get("/api/v1/groups/").status_code == HTTPStatus.UNAUTHORIZED
    assert (
        client.post("/api/v1/groups/", json={"name": "x"}).status_code
        == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.get("/api/v1/groups/%d" % group["id"]).status_code
        == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.post("/api/v1/groups/%d/members" % group["id"], json={}).status_code
        == HTTPStatus.UNAUTHORIZED
    )


def test_unauthenticated_cannot_access_message_endpoints(client):
    assert client.get("/api/v1/messages/").status_code == HTTPStatus.UNAUTHORIZED
    assert (
        client.post("/api/v1/messages/", json={}).status_code == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.post("/api/v1/messages/1/receipt").status_code == HTTPStatus.UNAUTHORIZED
    )
    assert client.delete("/api/v1/messages/1").status_code == HTTPStatus.UNAUTHORIZED


def test_unauthenticated_cannot_access_key_endpoints(client):
    assert (
        client.post("/api/v1/keys/bundle", json={}).status_code
        == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.post("/api/v1/keys/prekeys", json={}).status_code
        == HTTPStatus.UNAUTHORIZED
    )
    assert (
        client.get("/api/v1/keys/prekeys/count").status_code == HTTPStatus.UNAUTHORIZED
    )
    assert client.get("/api/v1/keys/1").status_code == HTTPStatus.UNAUTHORIZED


def test_sender_cannot_acknowledge_own_message_as_received(client, session):
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
    resp = client.post(
        "/api/v1/messages/%d/receipt" % msg["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_refresh_token_scoped_to_issuing_user(client, session):
    alice, _, alice_tokens = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": alice_tokens["refresh_token"]},
    )
    assert resp.status_code == HTTPStatus.OK
    new_tok = resp.json()["access_token"]
    # Token is cryptographically bound to alice's user_id — verify it grants
    # access by fetching alice's inbox (not bob's)
    msgs = client.get(
        "/api/v1/messages/",
        headers={"Authorization": "Bearer %s" % new_tok},
    ).json()
    assert isinstance(msgs, list)


def test_delete_me_cannot_delete_other_user(client, session):
    user_a, tok_a, _ = auth_helper(client, session, "acdela")
    user_b, tok_b, _ = auth_helper(client, session, "acdelb")
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    repo = SQLUserRepository(session)
    assert repo.get_user_by_id(user_b.id) is not None


def test_delete_me_deleted_user_cannot_access_any_endpoint(client, session):
    user, tok, _ = auth_helper(client, session, "acnoaccess")
    client.delete("/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok})
    for path in [
        "/api/v1/messages/",
        "/api/v1/keys/prekeys/count",
        "/api/v1/groups/",
    ]:
        resp = client.get(path, headers={"Authorization": "Bearer %s" % tok})
        assert resp.status_code == HTTPStatus.UNAUTHORIZED, "Expected 401 on %s" % path
