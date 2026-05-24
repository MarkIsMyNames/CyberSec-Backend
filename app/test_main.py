from http import HTTPStatus

from app.config import config
from app.security_tests.test_helper import auth_helper


def test_lifespan_initialises_database(client, session):
    # If init_db did not run, creating a user would raise (no table).
    auth_helper(client, session, "alice")


def test_openapi_json_disabled(client):
    assert client.get("/openapi.json").status_code == HTTPStatus.NOT_FOUND


def test_docs_disabled(client):
    assert client.get("/docs").status_code == HTTPStatus.NOT_FOUND


def test_redoc_disabled(client):
    assert client.get("/redoc").status_code == HTTPStatus.NOT_FOUND


def test_auth_router_mounted(client):
    resp = client.post("/api/v1/auth/register", json={})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_keys_router_mounted(client):
    assert client.get("/api/v1/keys/1").status_code == HTTPStatus.UNAUTHORIZED


def test_messages_router_mounted(client):
    assert client.get("/api/v1/messages/").status_code == HTTPStatus.UNAUTHORIZED


def test_groups_router_mounted(client):
    assert client.get("/api/v1/groups/").status_code == HTTPStatus.UNAUTHORIZED


def test_security_header_values(client):
    resp = client.post("/api/v1/auth/register", json={})
    headers = resp.headers
    srv = config["server"]
    assert (
        headers["strict-transport-security"]
        == "max-age=%d; includeSubDomains" % srv["time_for_enforced_http"]
    )
    assert headers["x-frame-options"] == srv["block_framing"]
    assert headers["x-content-type-options"] == srv["block_content_sniffing"]
    assert headers["content-security-policy"] == srv["allowed_content_sources"]
    assert headers["referrer-policy"] == srv["referrer_exposure"]
    assert "server" not in headers
