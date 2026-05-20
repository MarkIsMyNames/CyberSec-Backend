import pytest


@pytest.fixture(autouse=False)
def test_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_MASTER_SECRET", "a" * 64)
    monkeypatch.setenv("JWT_SECRET_KEY", "test_jwt_secret_key_32_bytes_long!")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))


@pytest.fixture
def db(test_env):
    from app.database import init_db
    init_db()


@pytest.fixture
def client(db):
    from app.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)
