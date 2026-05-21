from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any

import jwt

from app.config import config
from app.dependencies import open_session
from app.logger import logger
from app.repositories.user import SQLUserRepository


class InvalidTokenError(Exception):
    pass


_AUTH_CFG: dict[str, Any] = config["auth"]


def _secret() -> str:
    return os.environ["JWT_SECRET_KEY"]


def issue_access_token(user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "scope": "full",
        "exp": now + _AUTH_CFG["access_token_ttl_seconds"],
        "iat": now,
    }
    token = jwt.encode(payload, _secret(), algorithm=_AUTH_CFG["jwt_algorithm"])
    logger.debug("issued access token user_id=%d", user_id)
    return token


def issue_preauth_token(user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "scope": "totp_only",
        "jti": secrets.token_hex(16),
        "exp": now + _AUTH_CFG["preauth_token_ttl_seconds"],
        "iat": now,
    }
    token = jwt.encode(payload, _secret(), algorithm=_AUTH_CFG["jwt_algorithm"])
    logger.debug("issued preauth token user_id=%d", user_id)
    return token


def issue_refresh_token(user_id: int) -> tuple[str, str]:
    now = int(time.time())
    jti = secrets.token_hex(32)
    payload = {
        "sub": str(user_id),
        "scope": "refresh",
        "jti": jti,
        "exp": now + _AUTH_CFG["refresh_token_ttl_seconds"],
        "iat": now,
    }
    token = jwt.encode(payload, _secret(), algorithm=_AUTH_CFG["jwt_algorithm"])
    logger.debug("issued refresh token user_id=%d", user_id)
    return token, jti


def verify_token(token: str, expected_scope: str) -> dict[str, Any]:
    try:
        claims: dict[str, Any] = jwt.decode(
            token, _secret(), algorithms=[_AUTH_CFG["jwt_algorithm"]]
        )
    except jwt.PyJWTError as exc:
        logger.warning("token decode failed: %s", exc)
        raise InvalidTokenError(str(exc))

    if claims.get("scope") != expected_scope:
        logger.warning(
            "token scope mismatch expected=%s got=%s",
            expected_scope,
            claims.get("scope"),
        )
        raise InvalidTokenError("wrong scope")

    if "jti" in claims and expected_scope == "refresh":
        jti_hash = hashlib.sha256(claims["jti"].encode()).digest()
        with open_session() as session:
            repo = SQLUserRepository(session)
            if repo.is_refresh_token_blocked(jti_hash):
                raise InvalidTokenError("token revoked")

    logger.debug("token verified scope=%s", expected_scope)
    return claims


def blocklist_token(jti: str, expires_in_seconds: int) -> None:
    jti_hash = hashlib.sha256(jti.encode()).digest()
    expires_at = int(time.time()) + expires_in_seconds
    with open_session() as session:
        repo = SQLUserRepository(session)
        repo.block_refresh_token(jti_hash, expires_at)
    logger.info("token blocklisted expires_at=%d", expires_at)
