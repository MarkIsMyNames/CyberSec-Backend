from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import config

limiter = Limiter(key_func=get_remote_address)  # Limiter is per client

AUTH_LIMIT: str = config["rate_limits"]["auth"]
MESSAGES_LIMIT: str = config["rate_limits"]["messages"]
