import hashlib
import os
import secrets
import time
from collections.abc import Mapping
from typing import Any, TypedDict

import jwt

from app.config import config
from app.dependencies import open_session
from app.logger import logger
from app.repositories.user import SQLUserRepository


class InvalidTokenError(Exception):
    pass


class TokenClaims(TypedDict, total=False):
    sub: str
    scope: str
    jti: str
    exp: int
    iat: int


def parse_claims(raw: Mapping[str, object]) -> TokenClaims:
    claims: TokenClaims = {}
    if "sub" in raw:
        claims["sub"] = str(raw["sub"])
    if "scope" in raw:
        claims["scope"] = str(raw["scope"])
    if "jti" in raw:
        claims["jti"] = str(raw["jti"])
    if "exp" in raw:
        claims["exp"] = int(str(raw["exp"]))
    if "iat" in raw:
        claims["iat"] = int(str(raw["iat"]))
    return claims


AUTH_CFG: dict[str, Any] = config["auth"]


def _secret() -> str:
    return os.environ["JWT_SECRET_KEY"]


def _issue_token(user_id: int, scope: str, ttl_seconds: int, with_jti: bool) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "scope": scope,
        "exp": now + ttl_seconds,
        "iat": now,
    }
    if with_jti:
        payload["jti"] = secrets.token_hex(AUTH_CFG["secret_token_bytes"])
    token = jwt.encode(payload, _secret(), algorithm=AUTH_CFG["jwt_algorithm"])
    logger.debug("issued %s token user_id=%d", scope, user_id)
    return token


def issue_access_token(user_id: int) -> str:
    return _issue_token(
        user_id, "full", AUTH_CFG["access_token_ttl_seconds"], with_jti=False
    )


def issue_preauth_token(user_id: int) -> str:
    return _issue_token(
        user_id, "totp_only", AUTH_CFG["preauth_token_ttl_seconds"], with_jti=True
    )


def issue_refresh_token(user_id: int) -> str:
    return _issue_token(
        user_id, "refresh", AUTH_CFG["refresh_token_ttl_seconds"], with_jti=True
    )


def verify_token(token: str, expected_scope: str) -> TokenClaims:
    try:
        claims: TokenClaims = parse_claims(
            jwt.decode(token, _secret(), algorithms=[AUTH_CFG["jwt_algorithm"]])
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

    if "jti" in claims and expected_scope in ("refresh", "totp_only"):
        jti_hash = hashlib.sha256(claims["jti"].encode()).digest()
        with open_session() as session:
            repo = SQLUserRepository(session)
            if repo.is_refresh_token_blocked(jti_hash):
                raise InvalidTokenError("token revoked")

    logger.debug("token verified scope=%s", expected_scope)
    return claims


def revoke_token(claims: TokenClaims) -> None:
    # Prevents reuse of a still-valid JWT by storing its ID until natural expiry.
    jti_hash = hashlib.sha256(claims["jti"].encode()).digest()
    exp = int(claims["exp"])
    with open_session() as session:
        repo = SQLUserRepository(session)
        repo.block_refresh_token(jti_hash, exp)
    logger.info("token revoked expires_at=%d", exp)
