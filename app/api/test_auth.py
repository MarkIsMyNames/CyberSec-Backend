import base64
from http import HTTPStatus

import srp

from app.repositories.group import SQLGroupRepository
from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository
from app.security_tests.test_helper import auth_helper


def _register(client, username: str, password: str = "correcthorsebattery"):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )


def test_register_success(client):
    resp = _register(client, "alice")
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert "totp_provisioning_uri" in data
    assert data["totp_provisioning_uri"].startswith("otpauth://")


def test_register_duplicate_username(client):
    _register(client, "bob")
    resp = _register(client, "bob")
    assert resp.status_code == HTTPStatus.CONFLICT


def test_register_invalid_hex(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "carol",
            "srp_salt": "not-hex!",
            "srp_verifier": "deadbeef",
        },
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_srp_handshake_and_totp(client, session):
    _, access_token, tokens = auth_helper(client, session, "dave")
    assert access_token
    assert "access_token" in tokens
    assert "refresh_token" in tokens


def test_srp_wrong_password(client):
    _register(client, "eve")

    usr = srp.User("eve", "wrongpassword!!!", hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    username, client_public = usr.start_authentication()
    init = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": username,
            "client_public": client_public.hex(),
        },
    ).json()

    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    resp = client.post(
        "/api/v1/auth/srp-verify",
        json={
            "session_id": init["session_id"],
            "client_proof": client_proof.hex(),
        },
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_srp_unknown_user(client):
    usr = srp.User("nobody", "password123456", hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    _, client_public = usr.start_authentication()
    resp = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": "nobody",
            "client_public": client_public.hex(),
        },
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_refresh_token(client, session):
    _, _, tokens = auth_helper(client, session, "frank")
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert resp.status_code == HTTPStatus.OK
    assert "access_token" in resp.json()


def test_logout_blocklists_refresh_token(client, session):
    _, _, tokens = auth_helper(client, session, "grace")
    client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    resp = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_logout_with_invalid_token_returns_401(client):
    resp = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "not.a.valid.token"},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_refresh_with_invalid_token_returns_401(client):
    resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not.a.valid.token"},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


# --- DELETE /me endpoint ---

def test_delete_me_happy_path(client, session):
    user, access_token, _ = auth_helper(client, session, "delme_ok")
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT
    assert resp.content == b""


def test_delete_me_unauthenticated(client):
    resp = client.delete("/api/v1/auth/me")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_invalid_token(client):
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.valid.token"},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_user_gone_after_delete(client, session):
    user, access_token, _ = auth_helper(client, session, "delme_gone")
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    repo = SQLUserRepository(session)
    assert repo.get_user_by_id(user.id) is None


def test_delete_me_token_rejected_after_delete(client, session):
    user, access_token, _ = auth_helper(client, session, "delme_reject")
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    resp = client.get(
        "/api/v1/messages/",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_double_delete(client, session):
    user, access_token, _ = auth_helper(client, session, "delme_double")
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    resp = client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % access_token},
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_delete_me_does_not_affect_other_user(client, session):
    _, tok_a, _ = auth_helper(client, session, "delme_isoa")
    user_b, tok_b, _ = auth_helper(client, session, "delme_isob")
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    resp = client.get(
        "/api/v1/messages/",
        headers={"Authorization": "Bearer %s" % tok_b},
    )
    assert resp.status_code == HTTPStatus.OK


# --- cascade via endpoint ---

def test_delete_me_removes_sent_and_received_messages(client, session):
    user_a, tok_a, _ = auth_helper(client, session, "casc_msg_a")
    user_b, tok_b, _ = auth_helper(client, session, "casc_msg_b")
    _b64 = base64.b64encode(b"\x01" * 32).decode()
    client.post(
        "/api/v1/messages/",
        json={"recipient_id": user_b.id, "ciphertext": _b64, "ratchet_header_enc": _b64},
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    msg_repo = SQLMessageRepository(session)
    msgs_before = msg_repo.get_messages_for_user(user_b.id, limit=100, offset=0)
    assert len(msgs_before) > 0, "precondition: message must exist before delete"
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    msgs_after = msg_repo.get_messages_for_user(user_b.id, limit=100, offset=0)
    assert all(m.sender_id != user_a.id for m in msgs_after)


def test_delete_me_removes_group_membership(client, session):
    user_a, tok_a, _ = auth_helper(client, session, "casc_grp_a")
    user_b, tok_b, _ = auth_helper(client, session, "casc_grp_b")
    _b64 = base64.b64encode(b"\x02" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "cascgroup"},
        headers={"Authorization": "Bearer %s" % tok_b},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % grp_resp["id"],
        json={"user_id": user_a.id, "skdm_ciphertext": _b64},
        headers={"Authorization": "Bearer %s" % tok_b},
    )
    grp_repo = SQLGroupRepository(session)
    members_before = grp_repo.get_members(grp_resp["id"])
    assert user_a.id in members_before, "precondition: user_a must be a group member before delete"
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    members_after = grp_repo.get_members(grp_resp["id"])
    assert user_a.id not in members_after



def test_delete_me_removes_group_messages(client, session):
    user_a, tok_a, _ = auth_helper(client, session, "casc_gmsg_a")
    user_b, tok_b, _ = auth_helper(client, session, "casc_gmsg_b")
    _b64 = base64.b64encode(b"\x04" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "msggroup", "initial_members": {str(user_b.id): _b64}},
        headers={"Authorization": "Bearer %s" % tok_a},
    ).json()
    client.post(
        "/api/v1/groups/%d/messages" % grp_resp["id"],
        json={"epoch": 1, "ciphertext": _b64},
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    grp_repo = SQLGroupRepository(session)
    msgs_before = grp_repo.get_group_messages(grp_resp["id"], user_b.id)
    assert len(msgs_before) > 0, "precondition: group message must exist before delete"
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_a},
    )
    msgs_after = grp_repo.get_group_messages(grp_resp["id"], user_b.id)
    assert all(m.sender_id != user_a.id for m in msgs_after)


def test_delete_me_last_member_deletes_group(client, session):
    user, tok, _ = auth_helper(client, session, "casc_lastmem")
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "sologroup"},
        headers={"Authorization": "Bearer %s" % tok},
    ).json()
    group_id = grp_resp["id"]
    grp_repo = SQLGroupRepository(session)
    assert grp_repo.get_group(group_id) is not None, "precondition: group must exist before delete"
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert grp_repo.get_group(group_id) is None


# --- creator reassignment ---

def test_delete_creator_reassigns_to_remaining_member(client, session):
    creator, tok_c, _ = auth_helper(client, session, "reassign_creator")
    member, tok_m, _ = auth_helper(client, session, "reassign_member")
    _b64 = base64.b64encode(b"\x06" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "reassigngroup"},
        headers={"Authorization": "Bearer %s" % tok_c},
    ).json()
    group_id = grp_resp["id"]
    client.post(
        "/api/v1/groups/%d/members" % group_id,
        json={"user_id": member.id, "skdm_ciphertext": _b64},
        headers={"Authorization": "Bearer %s" % tok_c},
    )
    grp_repo = SQLGroupRepository(session)
    group_before = grp_repo.get_group(group_id)
    assert group_before is not None and group_before.creator_id == creator.id, \
        "precondition: creator must own group before delete"
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_c},
    )
    group = grp_repo.get_group(group_id)
    assert group is not None, "group must survive after creator deleted"
    assert group.creator_id == member.id, "creator must be reassigned to remaining member"


def test_delete_non_creator_does_not_change_creator(client, session):
    creator, tok_c, _ = auth_helper(client, session, "no_reassign_creator")
    member, tok_m, _ = auth_helper(client, session, "no_reassign_member")
    _b64 = base64.b64encode(b"\x08" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "nochangegroup"},
        headers={"Authorization": "Bearer %s" % tok_c},
    ).json()
    group_id = grp_resp["id"]
    client.post(
        "/api/v1/groups/%d/members" % group_id,
        json={"user_id": member.id, "skdm_ciphertext": _b64},
        headers={"Authorization": "Bearer %s" % tok_c},
    )
    client.delete(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer %s" % tok_m},
    )
    grp_repo = SQLGroupRepository(session)
    group = grp_repo.get_group(group_id)
    assert group is not None
    assert group.creator_id == creator.id
