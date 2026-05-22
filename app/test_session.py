import pytest
from sqlalchemy import text

from app.config import config
from app.session import _derive_db_key, get_engine


def test_derive_db_key_is_deterministic(test_env):
    assert _derive_db_key() == _derive_db_key()


def test_derive_db_key_length(test_env):
    expected_bytes = config["crypto"]["database_key_length_bytes"]
    assert len(bytes.fromhex(_derive_db_key())) == expected_bytes


def test_derive_db_key_requires_env(monkeypatch):
    monkeypatch.delenv("SERVER_MASTER_SECRET", raising=False)
    with pytest.raises(KeyError):
        _derive_db_key()


def test_get_engine_returns_singleton(test_env):
    assert get_engine() is get_engine()


def test_wal_mode_enabled(test_env, db):
    with get_engine().connect() as conn:
        mode = conn.execute(text("PRAGMA journal_mode")).scalar()
    assert mode == "wal"
