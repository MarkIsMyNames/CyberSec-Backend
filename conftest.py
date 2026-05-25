import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.auth.rate_limit import ip_limiter, limiter
from app.config import config
from app.database import init_db
from app.dependencies import get_session
from app.main import application
from app.session import reset_engine


def _admin_engine():
    return create_engine(os.environ["DATABASE_URL"], isolation_level="AUTOCOMMIT")


@pytest.fixture(autouse=False)
def test_env(monkeypatch):
    monkeypatch.setenv("SERVER_MASTER_SECRET", "a" * 64)
    monkeypatch.setenv("JWT_SECRET_KEY", "test_jwt_secret_key_for_ci_only_not_for_production")
    schema = "test_%s" % uuid.uuid4().hex
    monkeypatch.setenv("DATABASE_URL", _build_schema_url(schema))
    with _admin_engine().connect() as conn:
        conn.execute(text("CREATE SCHEMA %s" % schema))
    reset_engine()
    yield
    reset_engine()
    with _admin_engine().connect() as conn:
        conn.execute(text("DROP SCHEMA %s CASCADE" % schema))


def _build_schema_url(schema: str) -> str:
    base = os.environ["DATABASE_URL"]
    sep = "&" if "?" in base else "?"
    return "%s%soptions=-csearch_path%%3D%s" % (base, sep, schema)


@pytest.fixture
def db(test_env):
    init_db()


@pytest.fixture
def session(db):
    yield from get_session()


@pytest.fixture
def client(db):
    limiter.reset()
    ip_limiter.reset()
    with TestClient(application) as c:
        yield c


@pytest.fixture(autouse=True)
def high_limits(monkeypatch):
    """Raise all rate limits high enough that normal multi-user tests never trip them."""
    for key in config["rate_limits"]:
        monkeypatch.setitem(config["rate_limits"], key, "1000/minute")


@pytest.fixture
def low_limits(monkeypatch):
    """Patch all rate limits to 3/minute so tests need only 4 requests to trigger a 429."""
    for key in config["rate_limits"]:
        monkeypatch.setitem(config["rate_limits"], key, "3/minute")
