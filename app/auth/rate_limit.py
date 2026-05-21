from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import config

limiter = Limiter(key_func=get_remote_address)  # Limiter is per client

AUTH_LIMIT: str = config["rate_limits"]["auth"]
REFRESH_LIMIT: str = config["rate_limits"]["refresh"]
LOGOUT_LIMIT: str = config["rate_limits"]["logout"]
MESSAGES_LIMIT: str = config["rate_limits"]["messages"]
KEYS_LIMIT: str = config["rate_limits"]["keys"]
GROUP_LIMIT: str = config["rate_limits"]["groups"]
