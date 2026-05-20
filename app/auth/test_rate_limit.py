from app.auth.rate_limit import AUTH_LIMIT, MESSAGES_LIMIT, limiter
from app.config import config


def test_rate_limiter_exists():
    assert limiter is not None


def test_limit_strings():
    cfg = config["rate_limits"]
    assert AUTH_LIMIT == cfg["auth"]
    assert MESSAGES_LIMIT == cfg["messages"]
