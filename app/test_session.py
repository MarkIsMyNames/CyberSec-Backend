from sqlalchemy import text

from app.session import get_engine, reset_engine


def test_get_engine_returns_singleton(test_env):
    assert get_engine() is get_engine()


def test_reset_engine_clears_singleton(test_env):
    e1 = get_engine()
    reset_engine()
    e2 = get_engine()
    assert e1 is not e2


def test_engine_can_connect(test_env, db):
    with get_engine().connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
    assert result == 1
