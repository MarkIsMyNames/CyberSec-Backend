import os
from unittest.mock import MagicMock, patch

import pytest

from app.vault import load_secrets


def test_happy_path(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_ROLE_ID", "role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "secret-id")

    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "SERVER_MASTER_SECRET": "aaa",
                "JWT_SECRET_KEY": "bbb",
                "DATABASE_URL": "ccc",
            }
        }
    }

    with patch("app.vault.hvac.Client", return_value=mock_client):
        load_secrets()

    assert os.environ["SERVER_MASTER_SECRET"] == "aaa"
    assert os.environ["JWT_SECRET_KEY"] == "bbb"
    assert os.environ["DATABASE_URL"] == "ccc"


def test_missing_env_var(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)

    with pytest.raises(RuntimeError, match="Vault bootstrap failed"):
        load_secrets()


def test_vault_error(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_ROLE_ID", "role-id")
    monkeypatch.setenv("VAULT_SECRET_ID", "secret-id")

    mock_client = MagicMock()
    mock_client.auth.approle.login.side_effect = Exception("connection refused")

    with patch("app.vault.hvac.Client", return_value=mock_client):
        with pytest.raises(RuntimeError, match="Vault secret fetch failed"):
            load_secrets()
