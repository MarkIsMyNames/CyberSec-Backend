from http import HTTPStatus


def _probe(client):
    return client.post("/api/v1/auth/register", json={})


def test_hsts_header(client):
    resp = _probe(client)
    assert "strict-transport-security" in resp.headers
    assert "max-age=" in resp.headers["strict-transport-security"]


def test_x_frame_options(client):
    assert _probe(client).headers.get("x-frame-options") == "DENY"


def test_x_content_type_options(client):
    assert _probe(client).headers.get("x-content-type-options") == "nosniff"


def test_csp_header(client):
    assert "content-security-policy" in _probe(client).headers


def test_referrer_policy(client):
    assert _probe(client).headers.get("referrer-policy") == "no-referrer"


def test_no_server_header(client):
    assert "server" not in _probe(client).headers


def test_headers_present_on_non_200(client):
    resp = client.get("/api/v1/messages/")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert "strict-transport-security" in resp.headers
    assert "x-frame-options" in resp.headers
