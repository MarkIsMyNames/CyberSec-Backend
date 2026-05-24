import base64
from http import HTTPStatus

import srp

from app.security_tests.test_helper import auth_helper


def test_srp_init_sql_injection_in_username(client):
    usr = srp.User("victim' --", "anything", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, client_public = usr.start_authentication()
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={"username": "victim' --", "client_public": client_public.hex()},
    )
    assert resp.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.UNPROCESSABLE_ENTITY)


def test_group_name_with_sql_injection_stored_safely(client, session):
    _, alice_tok, _ = auth_helper(client, session, "alice")
    name = "'; DROP TABLE groups; --"
    group_id = client.post(
        "/api/v1/groups/",
        json={"name": name},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["id"]
    fetched = client.get(
        "/api/v1/groups/%d" % group_id,
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert fetched["name"] == name


def test_register_sql_injection_in_username(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "' OR '1'='1",
            "srp_salt": "deadbeef",
            "srp_verifier": "cafebabe",
        },
    )
    assert resp.status_code in (HTTPStatus.CREATED, HTTPStatus.UNPROCESSABLE_ENTITY)
    assert resp.status_code != HTTPStatus.INTERNAL_SERVER_ERROR


def test_message_ciphertext_with_injection_payload_stored_safely(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    payload = "'); DROP TABLE messages; --"
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": bob.id,
            "ciphertext": base64.b64encode(payload.encode()).decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.CREATED
    msgs = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    assert msgs[0]["ciphertext"] == base64.b64encode(payload.encode()).decode()


def test_group_message_with_injection_payload_stored_safely(client, session):
    _, alice_tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    payload = "'); DELETE FROM group_messages; --"
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={
            "epoch": 0,
            "ciphertext": base64.b64encode(payload.encode()).decode(),
        },
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.CREATED


def test_username_with_null_bytes_rejected_or_stored_safely(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "alice\x00evil",
            "srp_salt": "deadbeef",
            "srp_verifier": "cafebabe",
        },
    )
    assert resp.status_code != HTTPStatus.INTERNAL_SERVER_ERROR


def test_oversized_username_does_not_crash(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "a" * 10000,
            "srp_salt": "deadbeef",
            "srp_verifier": "cafebabe",
        },
    )
    assert resp.status_code != HTTPStatus.INTERNAL_SERVER_ERROR
