import jwt
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import config
from app.logger import logger


def _rate_limit_key(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer "):]
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            sub = claims.get("sub")
            if sub:
                logger.debug("rate limit key: user=%s path=%s", sub, request.url.path)
                return "user:%s" % sub
            logger.warning("rate limit key: bearer token missing sub claim path=%s ip=%s", request.url.path, get_remote_address(request))
        except jwt.DecodeError:
            logger.warning("rate limit key: malformed bearer token ip=%s path=%s", get_remote_address(request), request.url.path)
    else:
        logger.debug("rate limit key: no bearer token ip=%s path=%s", get_remote_address(request), request.url.path)
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)
ip_limiter = Limiter(key_func=get_remote_address)

AUTH_LIMIT: str = config["rate_limits"]["auth"]
REFRESH_LIMIT: str = config["rate_limits"]["refresh"]
LOGOUT_LIMIT: str = config["rate_limits"]["logout"]
MESSAGES_LIMIT: str = config["rate_limits"]["messages"]
KEYS_LIMIT: str = config["rate_limits"]["keys"]
GROUP_LIMIT: str = config["rate_limits"]["groups"]
IP_MESSAGES_LIMIT: str = config["rate_limits"]["ip_messages"]
IP_KEYS_LIMIT: str = config["rate_limits"]["ip_keys"]
IP_GROUP_LIMIT: str = config["rate_limits"]["ip_groups"]
