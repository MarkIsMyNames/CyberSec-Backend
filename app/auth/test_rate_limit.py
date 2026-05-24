import base64
import os
from http import HTTPStatus

import jwt
from fastapi import Request

from app.security_tests.test_helper import auth_helper
from app.auth.rate_limit import (
    auth_limit,
    group_limit,
    ip_group_limit,
    ip_keys_limit,
    ip_messages_limit,
    keys_limit,
    messages_limit,
    _rate_limit_key,
    ip_limiter,
    limiter,
)
from app.config import config


def _make_request(token: str | None = None, ip: str = "1.2.3.4") -> Request:
    headers = [(b"authorization", ("Bearer %s" % token).encode())] if token else []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": headers,
        "client": (ip, 0),
    }
    return Request(scope)


def _make_token(sub: str) -> str:
    return jwt.encode(
        {"sub": sub, "scope": "full", "exp": 9999999999},
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )


def test_rate_limiter_exists():
    assert limiter is not None
    assert ip_limiter is not None


def test_limit_strings_match_config():
    cfg = config["rate_limits"]
    assert auth_limit() == cfg["auth"]
    assert messages_limit() == cfg["messages"]
    assert keys_limit() == cfg["keys"]
    assert group_limit() == cfg["groups"]
    assert ip_messages_limit() == cfg["ip_messages"]
    assert ip_keys_limit() == cfg["ip_keys"]
    assert ip_group_limit() == cfg["ip_groups"]


def test_rate_limit_key_uses_user_id_for_bearer_token(test_env):
    token = _make_token("42")
    key = _rate_limit_key(_make_request(token=token))
    assert key == "user:42"


def test_rate_limit_key_falls_back_to_ip_without_token():
    key = _rate_limit_key(_make_request(ip="9.9.9.9"))
    assert key == "9.9.9.9"


def test_rate_limit_key_falls_back_to_ip_for_malformed_token():
    key = _rate_limit_key(_make_request(token="not.a.jwt", ip="5.5.5.5"))
    assert key == "5.5.5.5"


def _limit_count(limit_str: str) -> int:
    return int(limit_str.split("/")[0])


def test_per_user_message_limit_enforced(client, session, low_limits):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    limit = _limit_count(messages_limit())
    responses = [
        client.post(
            "/api/v1/messages/",
            json={
                "recipient_id": bob.id,
                "ciphertext": base64.b64encode(b"ct").decode(),
                "ratchet_header_enc": base64.b64encode(b"hdr").decode(),
            },
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
        for _ in range(limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in responses)


def test_per_user_group_limit_enforced(client, session, low_limits):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    limit = _limit_count(group_limit())
    responses = [
        client.post(
            "/api/v1/groups/",
            json={"name": "g%d" % i},
            headers={"Authorization": "Bearer %s" % alice_tok},
        )
        for i in range(limit + 1)
    ]
    assert any(r.status_code == HTTPStatus.TOO_MANY_REQUESTS for r in responses)
