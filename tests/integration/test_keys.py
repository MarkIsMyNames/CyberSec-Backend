from __future__ import annotations

import http
import httpx

from tests.integration.conftest import auth_headers, req, B64_32, BUNDLE_PAYLOAD


class TestKeys:
    def test_upload_bundle_happy_path(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/keys/bundle",
            headers=auth_headers(auth["access_token"]),
            json=BUNDLE_PAYLOAD,
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_upload_bundle_unauthenticated(self, client: httpx.Client):
        resp = req(client, "POST", "/api/v1/keys/bundle", json=BUNDLE_PAYLOAD)
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_upload_bundle_missing_fields(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/keys/bundle",
            headers=auth_headers(auth["access_token"]),
            json={"identity_pub": B64_32},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_upload_prekeys_happy_path(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/keys/prekeys",
            headers=auth_headers(auth["access_token"]),
            json={"one_time_prekeys": [B64_32]},
        )
        assert resp.status_code == http.HTTPStatus.NO_CONTENT

    def test_upload_prekeys_unauthenticated(self, client: httpx.Client):
        resp = req(
            client,
            "POST",
            "/api/v1/keys/prekeys",
            json={"one_time_prekeys": [B64_32]},
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_upload_prekeys_missing_fields(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/keys/prekeys",
            headers=auth_headers(auth["access_token"]),
            json={},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_get_prekey_count_happy_path(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/prekeys/count",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert resp.json()["count"] >= 0

    def test_get_prekey_count_unauthenticated(self, client: httpx.Client):
        resp = req(client, "GET", "/api/v1/keys/prekeys/count")
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_fetch_bundle_by_user_id(
        self, client: httpx.Client, auth_with_bundle: dict, second_user: dict
    ):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/%d" % auth_with_bundle["user_id"],
            headers=auth_headers(second_user["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert "identity_pub" in resp.json()

    def test_fetch_bundle_by_username(
        self, client: httpx.Client, auth_with_bundle: dict, second_user: dict
    ):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(second_user["access_token"]),
            params={"username": auth_with_bundle["username"]},
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert "user_id" in resp.json()

    def test_fetch_bundle_unknown_user_id(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/999999999",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND

    def test_fetch_bundle_unknown_username(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": "nosuchuser999"},
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND
