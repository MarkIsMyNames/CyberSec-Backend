from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import config

limiter = Limiter(key_func=get_remote_address)  # Limiter is per client

_cfg = config["rate_limits"]
AUTH_LIMIT: str = _cfg["auth"]
MESSAGES_LIMIT: str = _cfg["messages"]
