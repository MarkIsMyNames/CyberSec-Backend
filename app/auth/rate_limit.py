from collections.abc import Callable

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


def limit(key: str) -> Callable[[], str]:
    def getter() -> str:
        return str(config["rate_limits"][key])

    return getter


auth_limit = limit("auth")
refresh_limit = limit("refresh")
logout_limit = limit("logout")
messages_limit = limit("messages")
keys_limit = limit("keys")
group_limit = limit("groups")
ip_messages_limit = limit("ip_messages")
ip_keys_limit = limit("ip_keys")
ip_group_limit = limit("ip_groups")
ip_auth_limit = limit("ip_auth")
