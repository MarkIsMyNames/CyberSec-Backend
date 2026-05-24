from app.database import init_db
from app.models.base import Base


def test_init_db_creates_tables(test_env):
    init_db()
    expected = {
        "users",
        "user_key_bundles",
        "one_time_prekeys",
        "messages",
        "groups",
        "group_members",
        "group_messages",
        "group_message_receipts",
        "sender_key_distributions",
        "refresh_token_blocklist",
    }
    assert expected.issubset(Base.metadata.tables.keys())
