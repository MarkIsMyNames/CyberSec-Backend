import base64
import time
from http import HTTPStatus

import jwt as pyjwt
import srp

from app.security_tests.test_helper import auth_helper


def _srp_fields(username="validuser", password="correcthorsebattery"):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048
    )
    return {"srp_salt": salt.hex(), "srp_verifier": verifier.hex()}


def _key_bundle():
    return {
        "identity_pub": base64.b64encode(b"i" * 32).decode(),
        "signed_prekey_pub": base64.b64encode(b"s" * 32).decode(),
        "signed_prekey_sig": base64.b64encode(b"g" * 64).decode(),
        "one_time_prekeys": [base64.b64encode(b"o" * 32).decode()],
        "pq_prekey_pub": base64.b64encode(b"e" * 1184).decode(),
        "pq_prekey_sig": base64.b64encode(b"q" * 64).decode(),
    }


# --- Auth: register ---


def test_sql_injection_in_username(client):
    resp = client.post(
        "/api/v1/auth/register", json={"username": "' OR '1'='1", **_srp_fields()}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_oversized_username_rejected(client):
    resp = client.post(
        "/api/v1/auth/register", json={"username": "a" * 200, **_srp_fields()}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_null_bytes_in_username(client):
    resp = client.post(
        "/api/v1/auth/register", json={"username": "user\x00name", **_srp_fields()}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_missing_required_fields_rejected(client):
    resp = client.post("/api/v1/auth/register", json={"username": "alice"})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_extra_fields_ignored(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "validuser",
            "evil_field": "'; DROP TABLE users; --",
            **_srp_fields(),
        },
    )
    assert resp.status_code == HTTPStatus.CREATED


# --- Auth: srp-init username validation ---


def test_srp_init_rejects_short_username(client):
    resp = client.post(
        "/api/v1/auth/srp-init", json={"username": "ab", "client_public": "deadbeef"}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_init_rejects_oversized_username(client):
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={"username": "a" * 200, "client_public": "deadbeef"},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_init_rejects_special_chars_in_username(client):
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={"username": "ali ce!", "client_public": "deadbeef"},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Auth: verify-2fa totp_code validation ---


def test_verify_2fa_rejects_non_digit_totp(client):
    resp = client.post(
        "/api/v1/auth/verify-2fa", json={"totp_code": "abcdef", "pre_auth_token": "tok"}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_verify_2fa_rejects_short_totp(client):
    resp = client.post(
        "/api/v1/auth/verify-2fa", json={"totp_code": "12345", "pre_auth_token": "tok"}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_verify_2fa_rejects_long_totp(client):
    resp = client.post(
        "/api/v1/auth/verify-2fa",
        json={"totp_code": "1234567", "pre_auth_token": "tok"},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Messages: invalid base64 ---


def test_invalid_base64_ciphertext_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "user1")
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": 1,
            "ciphertext": "not_valid_base64!!!",
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_invalid_base64_ratchet_header_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "user1")
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": 1,
            "ciphertext": base64.b64encode(b"ct").decode(),
            "ratchet_header_enc": "not_valid_base64!!!",
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Keys: invalid base64 ---


def test_key_bundle_rejects_invalid_base64_identity(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    bundle = _key_bundle()
    bundle["identity_pub"] = "not!!base64"
    resp = client.post(
        "/api/v1/keys/bundle", json=bundle, headers={"Authorization": "Bearer %s" % tok}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_key_bundle_rejects_invalid_base64_one_time_prekey(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    bundle = _key_bundle()
    bundle["one_time_prekeys"] = ["not!!base64"]
    resp = client.post(
        "/api/v1/keys/bundle", json=bundle, headers={"Authorization": "Bearer %s" % tok}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_upload_prekeys_rejects_invalid_base64(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/keys/prekeys",
        json={"one_time_prekeys": ["not!!base64"]},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Groups: name validation ---


def test_create_group_rejects_empty_name(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/groups/",
        json={"name": ""},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_create_group_rejects_oversized_name(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/groups/",
        json={"name": "a" * 65},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Groups: invalid base64 ---


def test_group_message_rejects_invalid_base64(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"ciphertext": "not!!base64"},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_group_message_rejects_invalid_skdm_base64(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={
            "ciphertext": base64.b64encode(b"ct").decode(),
            "skdm_ciphertexts": {1: "not!!base64"},
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_group_message_rejects_non_int_skdm_key(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={
            "ciphertext": base64.b64encode(b"ct").decode(),
            "skdm_ciphertexts": {"notanid": base64.b64encode(b"skdm").decode()},
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Auth: hex field validation ---


def test_register_rejects_non_hex_srp_salt(client):
    fields = _srp_fields()
    fields["srp_salt"] = "not-hex!!"
    resp = client.post(
        "/api/v1/auth/register",
        json={"username": "validuser", **fields},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_register_rejects_non_hex_srp_verifier(client):
    fields = _srp_fields()
    fields["srp_verifier"] = "not-hex!!"
    resp = client.post(
        "/api/v1/auth/register",
        json={"username": "validuser", **fields},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_init_rejects_non_hex_client_public(client):
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={"username": "validuser", "client_public": "not-hex!!"},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_verify_rejects_non_hex_client_proof(client):
    resp = client.post(
        "/api/v1/auth/srp-verify",
        json={"session_id": "somesession", "client_proof": "not-hex!!"},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Messages: size limit and required fields ---


def test_message_ciphertext_too_large_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "user1")
    oversized = base64.b64encode(b"x" * (102400 + 1)).decode()
    resp = client.post(
        "/api/v1/messages/",
        json={
            "recipient_id": 1,
            "ciphertext": oversized,
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_message_missing_recipient_id_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "user1")
    resp = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": base64.b64encode(b"ct").decode(),
            "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
        },
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Groups: structural validation ---


def test_group_message_missing_epoch_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_skdm_rejects_empty_dict(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_add_member_rejects_invalid_base64_skdm(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": 2, "skdm_ciphertext": "not!!base64"},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_key_bundle_missing_required_field_rejected(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    bundle = _key_bundle()
    del bundle["pq_prekey_pub"]
    resp = client.post(
        "/api/v1/keys/bundle", json=bundle, headers={"Authorization": "Bearer %s" % tok}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_delete_me_malformed_jwt_structure(client):
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.even.close"},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_tampered_payload(client, session):
    user, _, _ = auth_helper(client, session, "iv_tamper")
    fake_token = pyjwt.encode(
        {"sub": str(user.id), "scope": "full", "exp": int(time.time()) + 900},
        "wrong_secret_key",
        algorithm="HS256",
    )
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % fake_token},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_wrong_scope_token(client, session):
    user, _, tokens = auth_helper(client, session, "iv_scope")
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tokens["refresh_token"]},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
