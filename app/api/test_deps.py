from http import HTTPStatus

from app.security_tests.test_helper import auth_helper

# --- get_current_user ---


def test_get_current_user_valid_token(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.get("/api/v1/messages/", headers={"Authorization": "Bearer %s" % tok})
    assert resp.status_code == HTTPStatus.OK


def test_get_current_user_missing_token(client):
    assert client.get("/api/v1/messages/").status_code == HTTPStatus.UNAUTHORIZED


def test_get_current_user_malformed_token(client):
    resp = client.get(
        "/api/v1/messages/", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_get_current_user_wrong_scope(client, session, test_env):
    from app.auth.tokens import issue_preauth_token

    tok = issue_preauth_token(user_id=999)
    resp = client.get("/api/v1/messages/", headers={"Authorization": "Bearer %s" % tok})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_get_current_user_deleted_user(client, session, test_env):
    from app.auth.tokens import issue_access_token

    tok = issue_access_token(user_id=99999)
    resp = client.get("/api/v1/messages/", headers={"Authorization": "Bearer %s" % tok})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


# --- require_valid_refresh ---


def test_require_valid_refresh_valid(client, session):
    _, _, tokens = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert resp.status_code == HTTPStatus.OK
    assert "access_token" in resp.json()
    assert "refresh_token" in resp.json()


def test_require_valid_refresh_invalid_token(client):
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "bad.token"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_require_valid_refresh_wrong_scope(client, session):
    _, access_tok, _ = auth_helper(client, session, "alice")
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": access_tok})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_require_valid_refresh_revokes_on_use(client, session):
    _, _, tokens = auth_helper(client, session, "alice")
    refresh = tokens["refresh_token"]
    client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


# --- require_preauth_user ---


def test_require_preauth_user_invalid_token(client):
    resp = client.post(
        "/api/v1/auth/verify-2fa",
        json={"totp_code": "123456", "pre_auth_token": "bad.token"},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_require_preauth_user_wrong_scope(client, session, test_env):
    from app.auth.tokens import issue_access_token

    tok = issue_access_token(user_id=1)
    resp = client.post(
        "/api/v1/auth/verify-2fa",
        json={"totp_code": "123456", "pre_auth_token": tok},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


# --- require_group_member ---


def test_require_group_member_nonexistent_group(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    resp = client.get(
        "/api/v1/groups/9999", headers={"Authorization": "Bearer %s" % tok}
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_require_group_member_not_a_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "private"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_require_group_member_is_member(client, session):
    _, tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "mine"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == HTTPStatus.OK
