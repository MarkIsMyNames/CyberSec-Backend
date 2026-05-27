from __future__ import annotations

import http
import ssl
import time
import uuid
from collections.abc import Generator
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
import pytest
import srp

BASE_URL = "https://BobbyTables.theburkenator.com"
REGISTER_MAX_ATTEMPTS = 50

B64_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
BUNDLE_PAYLOAD = {
    "identity_pub": B64_32,
    "signed_prekey_pub": B64_32,
    "signed_prekey_sig": B64_32,
    "one_time_prekeys": [B64_32],
    "pq_prekey_pub": B64_32,
    "pq_prekey_sig": B64_32,
}


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def req(
    client: httpx.Client,
    method: str,
    path: str,
    max_retries: int = 10,
    **kwargs,
) -> httpx.Response:
    for _ in range(max_retries - 1):
        resp = client.request(method, path, **kwargs)
        if resp.status_code != http.HTTPStatus.TOO_MANY_REQUESTS:
            return resp
        retry_after = int(resp.headers.get("Retry-After", "60"))
        time.sleep(retry_after)
    return client.request(method, path, **kwargs)


def make_username() -> str:
    return uuid.uuid4().hex


def _extract_totp_secret(provisioning_uri: str) -> str:
    parsed = urlparse(provisioning_uri)
    return parse_qs(parsed.query)["secret"][0]


def register(client: httpx.Client, username: str, password: str) -> dict:
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    for _ in range(REGISTER_MAX_ATTEMPTS):
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
        if resp.status_code == http.HTTPStatus.CREATED:
            totp_secret = _extract_totp_secret(resp.json()["totp_provisioning_uri"])
            return {
                "username": username,
                "password": password,
                "srp_salt": salt.hex(),
                "srp_verifier": verifier.hex(),
                "totp_secret": totp_secret,
            }
        if resp.status_code == http.HTTPStatus.CONFLICT:
            username = make_username()
            salt, verifier = srp.create_salted_verification_key(
                username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
            )
    pytest.fail("Failed to register after 50 attempts")
    raise AssertionError("unreachable")


def srp_login(client: httpx.Client, username: str, password: str) -> str:
    usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    _, client_public = usr.start_authentication()
    init = req(
        client,
        "POST",
        "/api/v1/auth/srp-init",
        json={"username": username, "client_public": client_public.hex()},
    ).json()
    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    srp_resp = req(
        client,
        "POST",
        "/api/v1/auth/srp-verify",
        json={"session_id": init["session_id"], "client_proof": client_proof.hex()},
    ).json()
    return srp_resp["pre_auth_token"]


def totp_verify(client: httpx.Client, pre_auth_token: str, totp_secret: str) -> dict:
    code = pyotp.TOTP(totp_secret).now()
    result: dict = req(
        client,
        "POST",
        "/api/v1/auth/verify-2fa",
        json={"totp_code": code, "pre_auth_token": pre_auth_token},
    ).json()
    return result


def full_auth(client: httpx.Client, password: str = "IntegrationTest1") -> dict:
    creds: dict = register(client, make_username(), password)
    for _ in range(REGISTER_MAX_ATTEMPTS):
        pre_auth = srp_login(client, creds["username"], password)
        tokens = totp_verify(client, pre_auth, creds["totp_secret"])
        if "access_token" in tokens:
            return {
                "username": creds["username"],
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "totp_secret": creds["totp_secret"],
            }
        time.sleep(int(tokens.get("retry_after", 2)))
    pytest.fail("full_auth: failed to obtain tokens after %d attempts" % REGISTER_MAX_ATTEMPTS)
    raise AssertionError("unreachable")


def auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": "Bearer %s" % access_token}


def refresh_access_token(client: httpx.Client, refresh_token: str) -> str:
    resp = req(client, "POST", "/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    return resp.json()["access_token"]


def delete_user(client: httpx.Client, access_token: str) -> None:
    req(client, "DELETE", "/api/v1/auth/me", headers=auth_headers(access_token))


@pytest.fixture(scope="session")
def client() -> Generator[httpx.Client, None, None]:
    with httpx.Client(verify=_make_ssl_context(), base_url=BASE_URL, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="session")
def auth(client: httpx.Client) -> Generator[dict, None, None]:
    user = full_auth(client)
    yield user
    fresh_token = refresh_access_token(client, user["refresh_token"])
    delete_user(client, fresh_token)


@pytest.fixture
def ephemeral_user(client: httpx.Client) -> Generator[dict, None, None]:
    user = full_auth(client)
    yield user
    delete_user(client, user["access_token"])


@pytest.fixture
def second_user(client: httpx.Client) -> Generator[dict, None, None]:
    user = full_auth(client)
    req(
        client,
        "POST",
        "/api/v1/keys/bundle",
        headers=auth_headers(user["access_token"]),
        json=BUNDLE_PAYLOAD,
    )
    yield user
    delete_user(client, user["access_token"])


@pytest.fixture(scope="session")
def auth_with_bundle(client: httpx.Client, auth: dict) -> dict:
    req(
        client,
        "POST",
        "/api/v1/keys/bundle",
        headers=auth_headers(auth["access_token"]),
        json=BUNDLE_PAYLOAD,
    )
    user_id_resp = req(
        client,
        "GET",
        "/api/v1/keys/lookup/by-username",
        headers=auth_headers(auth["access_token"]),
        params={"username": auth["username"]},
    )
    user_id = user_id_resp.json()["user_id"]
    return {**auth, "user_id": user_id}
