import pytest
from fastapi.testclient import TestClient

from app.auth.rate_limit import limiter
from app.config import config
from app.database import init_db
from app.dependencies import get_session
from app.main import app


@pytest.fixture(autouse=False)
def test_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_MASTER_SECRET", "a" * 64)
    monkeypatch.setenv("JWT_SECRET_KEY", "test_jwt_secret_key_32_bytes_long!")
    monkeypatch.setitem(config["server"], "db_path", str(tmp_path / "test.db"))


@pytest.fixture
def db(test_env):
    init_db()


@pytest.fixture
def session(db):
    yield from get_session()


@pytest.fixture
def client(db):
    limiter.reset()
    with TestClient(app) as c:
        yield c
