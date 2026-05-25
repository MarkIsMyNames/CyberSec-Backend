import jwt
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import config
from app.logger import logger


def _rate_limit_key(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            claims = jwt.decode(
                auth[len("Bearer ") :], options={"verify_signature": False}
            )
            if sub := claims.get("sub"):
                logger.debug("rate limit key: user=%s path=%s", sub, request.url.path)
                return "user:%s" % sub
        except jwt.DecodeError:
            logger.warning(
                "rate limit key: malformed bearer token ip=%s path=%s",
                get_remote_address(request),
                request.url.path,
            )
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)


def auth_limit() -> str:
    return str(config["rate_limits"]["auth"])


def refresh_limit() -> str:
    return str(config["rate_limits"]["refresh"])


def logout_limit() -> str:
    return str(config["rate_limits"]["logout"])


def messages_limit() -> str:
    return str(config["rate_limits"]["messages"])


def keys_limit() -> str:
    return str(config["rate_limits"]["keys"])


def group_limit() -> str:
    return str(config["rate_limits"]["groups"])


def ip_messages_limit() -> str:
    return str(config["rate_limits"]["ip_messages"])


def ip_keys_limit() -> str:
    return str(config["rate_limits"]["ip_keys"])


def ip_group_limit() -> str:
    return str(config["rate_limits"]["ip_groups"])


def ip_auth_limit() -> str:
    return str(config["rate_limits"]["ip_auth"])
