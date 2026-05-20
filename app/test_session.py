import pytest


def test_derive_db_key_is_deterministic(test_env):
    from app.session import _derive_db_key
    assert _derive_db_key() == _derive_db_key()


def test_derive_db_key_length(test_env):
    from app.config import get_config
    from app.session import _derive_db_key
    expected_bytes = get_config()["crypto"]["database_key_length_bytes"]
    assert len(bytes.fromhex(_derive_db_key())) == expected_bytes


def test_derive_db_key_requires_env(monkeypatch):
    monkeypatch.delenv("SERVER_MASTER_SECRET", raising=False)
    from app.session import _derive_db_key
    with pytest.raises(KeyError):
        _derive_db_key()
