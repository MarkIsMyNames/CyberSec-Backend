import pytest


@pytest.fixture(autouse=False)
def test_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_MASTER_SECRET", "a" * 64)
    monkeypatch.setenv("JWT_SECRET_KEY", "test_jwt_secret_key_32_bytes_long!")
    import app.config as _cfg
    cfg = {**_cfg.get_config()}
    cfg["server"] = {**cfg["server"], "db_path": str(tmp_path / "test.db")}
    monkeypatch.setattr(_cfg, "config", cfg)


@pytest.fixture
def db(test_env):
    from app.database import init_db
    init_db()


@pytest.fixture
def session(db):
    from app.dependencies import get_session
    yield from get_session()


@pytest.fixture
def client(db):
    from app.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)
