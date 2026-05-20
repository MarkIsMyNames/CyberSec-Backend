def test_rate_limiter_exists():
    from app.auth.rate_limit import limiter
    assert limiter is not None


def test_limit_strings():
    from app.auth.rate_limit import AUTH_LIMIT, MESSAGES_LIMIT
    from app.config import get_config
    cfg = get_config()["rate_limits"]
    assert AUTH_LIMIT == cfg["auth"]
    assert MESSAGES_LIMIT == cfg["messages"]
