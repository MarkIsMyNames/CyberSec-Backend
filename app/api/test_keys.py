import base64
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper


def _make_bundle():
    return {
        "identity_pub": base64.b64encode(b"i" * 32).decode(),
        "signed_prekey_pub": base64.b64encode(b"s" * 32).decode(),
        "signed_prekey_sig": base64.b64encode(b"g" * 64).decode(),
        "one_time_prekeys": [
            base64.b64encode(bytes([i] * 32)).decode() for i in range(3)
        ],
        "pq_prekey_pub": base64.b64encode(b"e" * 1184).decode(),
        "pq_prekey_sig": base64.b64encode(b"q" * 64).decode(),
    }


def test_publish_and_fetch_key_bundle(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bundle = _make_bundle()
    resp = client.post(
        "/api/v1/keys/bundle",
        json=bundle,
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT

    _, bob_tok, _ = auth_helper(client, session, "bob")
    fetch = client.get(
        "/api/v1/keys/%d" % alice.id, headers={"Authorization": "Bearer %s" % bob_tok}
    )
    assert fetch.status_code == HTTPStatus.OK
    data = fetch.json()
    assert data["identity_pub"] == bundle["identity_pub"]
    assert data["one_time_prekey"] is not None


def test_fetch_pops_one_time_prekey(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    client.post(
        "/api/v1/keys/bundle",
        json=_make_bundle(),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    _, bob_tok, _ = auth_helper(client, session, "bob")
    r1 = client.get(
        "/api/v1/keys/%d" % alice.id, headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    r2 = client.get(
        "/api/v1/keys/%d" % alice.id, headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()
    assert r1["one_time_prekey"] != r2["one_time_prekey"]


def test_upload_additional_prekeys(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    client.post(
        "/api/v1/keys/bundle",
        json=_make_bundle(),
        headers={"Authorization": "Bearer %s" % tok},
    )
    resp = client.post(
        "/api/v1/keys/prekeys",
        json={"one_time_prekeys": [base64.b64encode(b"n" * 32).decode()]},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT


def test_prekey_count(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    client.post(
        "/api/v1/keys/bundle",
        json=_make_bundle(),
        headers={"Authorization": "Bearer %s" % tok},
    )
    resp = client.get("/api/v1/keys/prekeys/count", headers={"Authorization": "Bearer %s" % tok})
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["count"] == 3


def test_endpoints_reject_invalid_token(client, session):
    bad = {"Authorization": "Bearer not.a.real.token"}
    bundle = _make_bundle()
    assert client.post("/api/v1/keys/bundle", json=bundle, headers=bad).status_code == HTTPStatus.UNAUTHORIZED
    assert client.post("/api/v1/keys/prekeys", json={"one_time_prekeys": []}, headers=bad).status_code == HTTPStatus.UNAUTHORIZED
    assert client.get("/api/v1/keys/prekeys/count", headers=bad).status_code == HTTPStatus.UNAUTHORIZED
    assert client.get("/api/v1/keys/1", headers=bad).status_code == HTTPStatus.UNAUTHORIZED


def test_endpoints_require_auth(client, session):
    bundle = _make_bundle()
    assert client.post("/api/v1/keys/bundle", json=bundle).status_code == HTTPStatus.FORBIDDEN
    assert client.post("/api/v1/keys/prekeys", json={"one_time_prekeys": []}).status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/keys/prekeys/count").status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/keys/1").status_code == HTTPStatus.FORBIDDEN


def test_fetch_nonexistent_user_returns_404(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.get("/api/v1/keys/9999", headers={"Authorization": "Bearer %s" % tok})
    assert resp.status_code == HTTPStatus.NOT_FOUND
