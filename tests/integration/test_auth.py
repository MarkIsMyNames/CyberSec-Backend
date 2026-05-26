from __future__ import annotations

import http
import httpx
import srp

from tests.integration.conftest import (
    auth_headers,
    full_auth,
    make_username,
    register,
    req,
    srp_login,
)


class TestAuth:
    def test_register_happy_path(self, client: httpx.Client):
        creds = register(client, make_username(), "HappyReg1")
        assert "totp_secret" in creds

    def test_register_duplicate_username(self, client: httpx.Client):
        username = make_username()
        salt, verifier = srp.create_salted_verification_key(
            username, "pass1", hash_alg=srp.SHA256, ng_type=srp.NG_4096
        )
        req(
            client,
            "POST",
            "/api/v1/auth/register",
            json={
                "username": username,
                "srp_salt": salt.hex(),
                "srp_verifier": verifier.hex(),
            },
        )
        resp = req(
            client,
            "POST",
            "/api/v1/auth/register",
            json={
                "username": username,
                "srp_salt": salt.hex(),
                "srp_verifier": verifier.hex(),
            },
        )
        assert resp.status_code == http.HTTPStatus.CONFLICT

    def test_register_missing_fields(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/auth/register", json={"username": "abc"})
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_register_response_no_secret_fields(self, client: httpx.Client):
        username = make_username()
        salt, verifier = srp.create_salted_verification_key(
            username, "NoSecret1", hash_alg=srp.SHA256, ng_type=srp.NG_4096
        )
        resp = req(
            client,
            "POST",
            "/api/v1/auth/register",
            json={
                "username": username,
                "srp_salt": salt.hex(),
                "srp_verifier": verifier.hex(),
            },
        )
        body = resp.text.lower()
        for key in ("password", "verifier_enc", "totp_secret_enc", "srp_verifier_enc"):
            assert key not in body

    def test_srp_init_happy_path(self, client: httpx.Client, auth: dict):
        usr = srp.User(
            auth["username"],
            "IntegrationTest1",
            hash_alg=srp.SHA256,
            ng_type=srp.NG_4096,
        )
        _, client_public = usr.start_authentication()
        resp = req(
            client,
            "POST",
            "/api/v1/auth/srp-init",
            json={"username": auth["username"], "client_public": client_public.hex()},
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert "session_id" in resp.json()

    def test_srp_init_unknown_user(self, client: httpx.Client):
        usr = srp.User(
            "nosuchuser000", "pass", hash_alg=srp.SHA256, ng_type=srp.NG_4096
        )
        _, client_public = usr.start_authentication()
        resp = req(
            client,
            "POST",
            "/api/v1/auth/srp-init",
            json={"username": "nosuchuser000", "client_public": client_public.hex()},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_srp_init_missing_fields(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/auth/srp-init", json={"username": "abc"})
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_srp_verify_invalid_session(self, client: httpx.Client):
        resp = req(
            client,
            "POST",
            "/api/v1/auth/srp-verify",
            json={
                "session_id": "00000000-0000-0000-0000-000000000000",
                "client_proof": "deadbeef",
            },
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_2fa_wrong_code(self, client: httpx.Client):
        creds = register(client, make_username(), "TwoFAWrong1")
        pre_auth = srp_login(client, creds["username"], "TwoFAWrong1")
        resp = req(
            client,
            "POST",
            "/api/v1/auth/verify-2fa",
            json={"totp_code": "000000", "pre_auth_token": pre_auth},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_2fa_missing_code(self, client: httpx.Client):
        creds = register(client, make_username(), "TwoFAMiss1")
        pre_auth = srp_login(client, creds["username"], "TwoFAMiss1")
        resp = req(
            client,
            "POST",
            "/api/v1/auth/verify-2fa",
            json={"pre_auth_token": pre_auth},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_refresh_happy_path(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/auth/refresh",
            json={"refresh_token": auth["refresh_token"]},
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert "access_token" in resp.json()

    def test_refresh_with_access_token_fails(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/auth/refresh",
            json={"refresh_token": auth["access_token"]},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_refresh_no_token(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/auth/refresh", json={})
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_logout_happy_path(self, client: httpx.Client):
        user = full_auth(client)
        resp = req(
            client,
            "POST",
            "/api/v1/auth/logout",
            json={"refresh_token": user["refresh_token"]},
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_logout_no_token(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/auth/logout", json={})
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_logout_after_logout_fails(self, client: httpx.Client):
        user = full_auth(client)
        req(
            client,
            "POST",
            "/api/v1/auth/logout",
            json={"refresh_token": user["refresh_token"]},
        )
        resp = req(
            client,
            "POST",
            "/api/v1/auth/logout",
            json={"refresh_token": user["refresh_token"]},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_delete_me_happy_path(self, client: httpx.Client, ephemeral_user: dict):
        resp = req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(ephemeral_user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_delete_me_unauthenticated(self, client: httpx.Client):
        resp = req(client, "DELETE", "/api/v1/auth/me")
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_delete_me_invalid_token(self, client: httpx.Client):
        resp = req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer garbage"},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_delete_me_double_delete(self, client: httpx.Client):
        user = full_auth(client)
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user["access_token"]),
        )
        resp = req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_delete_me_token_rejected_on_all_endpoints(self, client: httpx.Client):
        user = full_auth(client)
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user["access_token"]),
        )
        for method, path in [("GET", "/api/v1/messages/"), ("GET", "/api/v1/groups/")]:
            resp = req(
                client, method, path, headers=auth_headers(user["access_token"])
            )
            assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_delete_me_does_not_affect_other_user(
        self, client: httpx.Client, second_user: dict
    ):
        user_a = full_auth(client)
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user_a["access_token"]),
        )
        resp = req(
            client,
            "GET",
            "/api/v1/messages/",
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK

    def test_delete_me_removes_key_bundle(self, client: httpx.Client):
        user = full_auth(client)
        _b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        req(
            client,
            "POST",
            "/api/v1/keys/bundle",
            headers=auth_headers(user["access_token"]),
            json={
                "identity_pub": _b64,
                "signed_prekey_pub": _b64,
                "signed_prekey_sig": _b64,
                "one_time_prekeys": [_b64],
                "pq_prekey_pub": _b64,
                "pq_prekey_sig": _b64,
            },
        )
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(user["access_token"]),
            params={"username": user["username"]},
        )
        assert lookup.status_code == http.HTTPStatus.OK
        user_id = lookup.json()["user_id"]
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user["access_token"]),
        )
        second = full_auth(client)
        bundle_resp = req(
            client,
            "GET",
            "/api/v1/keys/%d" % user_id,
            headers=auth_headers(second["access_token"]),
        )
        assert bundle_resp.status_code == http.HTTPStatus.NOT_FOUND
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(second["access_token"]),
        )

    def test_delete_me_removes_received_messages(
        self, client: httpx.Client, auth: dict
    ):
        _b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        user_a = full_auth(client)
        req(
            client,
            "POST",
            "/api/v1/keys/bundle",
            headers=auth_headers(user_a["access_token"]),
            json={
                "identity_pub": _b64,
                "signed_prekey_pub": _b64,
                "signed_prekey_sig": _b64,
                "one_time_prekeys": [_b64],
                "pq_prekey_pub": _b64,
                "pq_prekey_sig": _b64,
            },
        )
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": user_a["username"]},
        )
        assert lookup.status_code == http.HTTPStatus.OK
        user_a_id = lookup.json()["user_id"]
        send_resp = req(
            client,
            "POST",
            "/api/v1/messages/",
            headers=auth_headers(auth["access_token"]),
            json={"recipient_id": user_a_id, "ciphertext": _b64, "ratchet_header_enc": _b64},
        )
        assert send_resp.status_code == http.HTTPStatus.CREATED
        msg_id = send_resp.json()["id"]
        req(client, "DELETE", "/api/v1/auth/me", headers=auth_headers(user_a["access_token"]))
        witness = full_auth(client)
        receipt_resp = req(
            client,
            "POST",
            "/api/v1/messages/%d/receipt" % msg_id,
            headers=auth_headers(witness["access_token"]),
        )
        assert receipt_resp.status_code == http.HTTPStatus.NOT_FOUND, (
            "message should be deleted with user, got %d" % receipt_resp.status_code
        )
        req(client, "DELETE", "/api/v1/auth/me", headers=auth_headers(witness["access_token"]))

    def test_delete_me_removes_group_membership(
        self, client: httpx.Client, second_user: dict
    ):
        user_a = full_auth(client)
        _b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        grp_resp = req(
            client,
            "POST",
            "/api/v1/groups/",
            headers=auth_headers(second_user["access_token"]),
            json={"name": "testdeletegrp"},
        ).json()
        lookup = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(second_user["access_token"]),
            params={"username": user_a["username"]},
        )
        user_a_id: int | None = None
        if lookup.status_code == http.HTTPStatus.OK:
            user_a_id = lookup.json()["user_id"]
            req(
                client,
                "POST",
                "/api/v1/groups/%d/members" % grp_resp["id"],
                headers=auth_headers(second_user["access_token"]),
                json={"user_id": user_a_id, "skdm_ciphertext": _b64},
            )
        req(
            client,
            "DELETE",
            "/api/v1/auth/me",
            headers=auth_headers(user_a["access_token"]),
        )
        grp_detail = req(
            client,
            "GET",
            "/api/v1/groups/%d" % grp_resp["id"],
            headers=auth_headers(second_user["access_token"]),
        ).json()
        members = grp_detail.get("members", [])
        if user_a_id is not None:
            assert user_a_id not in members
