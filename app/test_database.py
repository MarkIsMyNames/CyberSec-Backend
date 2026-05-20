import pytest


def test_init_db_creates_tables(test_env):
    from app.database import init_db, Base
    init_db()
    expected = {
        "users", "identity_keys", "one_time_prekeys", "pq_prekeys",
        "messages", "groups", "group_members",
        "group_messages", "group_message_receipts",
        "sender_key_distributions", "refresh_token_blocklist",
    }
    assert expected.issubset(Base.metadata.tables.keys())


def test_get_session_requires_env(monkeypatch):
    monkeypatch.delenv("SERVER_MASTER_SECRET", raising=False)
    with pytest.raises(KeyError):
        from app.dependencies import get_session
        next(get_session())
