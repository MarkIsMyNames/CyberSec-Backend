from __future__ import annotations

import http
import httpx
import pytest

from tests.integration.conftest import auth_headers, req, B64_32


class TestMessages:
    def test_send_message(self, client: httpx.Client, auth: dict, second_user: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/keys/lookup/by-username",
            headers=auth_headers(auth["access_token"]),
            params={"username": second_user["username"]},
        )
        if resp.status_code != http.HTTPStatus.OK:
            pytest.skip("second_user has no user_id available (no bundle)")
        recipient_id = resp.json()["user_id"]
        resp = req(
            client,
            "POST",
            "/api/v1/messages/",
            headers=auth_headers(auth["access_token"]),
            json={
                "recipient_id": recipient_id,
                "ciphertext": B64_32,
                "ratchet_header_enc": B64_32,
            },
        )
        assert resp.status_code == http.HTTPStatus.CREATED
        assert "id" in resp.json()

    def test_send_message_unauthenticated(self, client: httpx.Client):
        resp = req(
            client,
            "POST",
            "/api/v1/messages/",
            json={
                "recipient_id": 1,
                "ciphertext": B64_32,
                "ratchet_header_enc": B64_32,
            },
        )
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_send_message_missing_fields(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/messages/",
            headers=auth_headers(auth["access_token"]),
            json={"recipient_id": 1},
        )
        assert resp.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY

    def test_list_messages(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/messages/",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.OK
        assert isinstance(resp.json(), list)

    def test_list_messages_unauthenticated(self, client: httpx.Client):
        resp = req(client, "GET", "/api/v1/messages/")
        assert resp.status_code == http.HTTPStatus.UNAUTHORIZED

    def test_mark_receipt_nonexistent(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "POST",
            "/api/v1/messages/999999999/receipt",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code == http.HTTPStatus.NOT_FOUND

    def test_delete_message_nonexistent(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "DELETE",
            "/api/v1/messages/999999999",
            headers=auth_headers(auth["access_token"]),
        )
        assert resp.status_code in (http.HTTPStatus.NOT_FOUND, http.HTTPStatus.FORBIDDEN)
