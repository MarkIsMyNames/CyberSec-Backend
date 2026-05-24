def test_hsts_header(client):
    resp = client.get("/api/v1/health")
    assert "strict-transport-security" in resp.headers
    assert "max-age=" in resp.headers["strict-transport-security"]


def test_x_frame_options(client):
    resp = client.get("/api/v1/health")
    assert resp.headers.get("x-frame-options") == "DENY"


def test_x_content_type_options(client):
    resp = client.get("/api/v1/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"


def test_csp_header(client):
    resp = client.get("/api/v1/health")
    assert "content-security-policy" in resp.headers


def test_no_server_header(client):
    resp = client.get("/api/v1/health")
    assert "server" not in resp.headers
