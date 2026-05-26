from __future__ import annotations

import http
import socket
import ssl

import httpx
import srp

from tests.integration.conftest import auth_headers, make_username, req


class TestTLS:
    def test_tls_1_2_or_higher_negotiated(self):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(
            ("BobbyTables.theburkenator.com", 443), timeout=10
        ) as sock:
            with ctx.wrap_socket(
                sock, server_hostname="BobbyTables.theburkenator.com"
            ) as ssock:
                assert ssock.version() in ("TLSv1.2", "TLSv1.3")

    def test_certificate_valid(self, client: httpx.Client):
        resp = req(client, "GET", "/api/v1/auth/register", json={})
        assert resp.status_code != 0

    def test_http_not_2xx(self):
        with httpx.Client(follow_redirects=False, timeout=10.0) as plain:
            resp = plain.get("http://BobbyTables.theburkenator.com/api/v1/auth/register")
        assert resp.status_code not in range(200, 300)

    def test_security_headers_present(self, client: httpx.Client, auth: dict):
        resp = req(
            client,
            "GET",
            "/api/v1/messages/",
            headers=auth_headers(auth["access_token"]),
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        assert "strict-transport-security" in headers
        assert "x-frame-options" in headers
        assert "x-content-type-options" in headers
        assert "content-security-policy" in headers
        assert "referrer-policy" in headers

    def test_no_sensitive_data_in_register_response(self, client: httpx.Client):
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

    def test_all_protected_endpoints_reject_no_token(self, client: httpx.Client):
        protected = [
            ("GET", "/api/v1/messages/"),
            ("GET", "/api/v1/keys/prekeys/count"),
            ("GET", "/api/v1/groups/"),
            ("DELETE", "/api/v1/auth/me"),
        ]
        for method, path in protected:
            resp = req(client, method, path)
            assert resp.status_code == http.HTTPStatus.UNAUTHORIZED, "Expected 401 on %s %s" % (method, path)

    def test_all_protected_endpoints_reject_invalid_token(self, client: httpx.Client):
        protected = [
            ("GET", "/api/v1/messages/"),
            ("GET", "/api/v1/keys/prekeys/count"),
            ("GET", "/api/v1/groups/"),
            ("DELETE", "/api/v1/auth/me"),
        ]
        bad_headers = {"Authorization": "Bearer garbage.token.here"}
        for method, path in protected:
            resp = req(client, method, path, headers=bad_headers)
            assert resp.status_code == http.HTTPStatus.UNAUTHORIZED, "Expected 401 on %s %s" % (method, path)
