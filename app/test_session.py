import pytest

from app.config import config
from app.session import _derive_db_key


def test_derive_db_key_is_deterministic(test_env):
    assert _derive_db_key() == _derive_db_key()


def test_derive_db_key_length(test_env):
    expected_bytes = config["crypto"]["database_key_length_bytes"]
    assert len(bytes.fromhex(_derive_db_key())) == expected_bytes


def test_derive_db_key_requires_env(monkeypatch):
    monkeypatch.delenv("SERVER_MASTER_SECRET", raising=False)
    with pytest.raises(KeyError):
        _derive_db_key()
