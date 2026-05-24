import base64
from http import HTTPStatus

from app.security_tests.test_helper import auth_helper


def test_list_groups(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    g1 = client.post(
        "/api/v1/groups/",
        json={"name": "g1"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    g2 = client.post(
        "/api/v1/groups/",
        json={"name": "g2"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % g1["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    alice_groups = client.get(
        "/api/v1/groups/", headers={"Authorization": "Bearer %s" % alice_tok}
    ).json()["groups"]
    bob_groups = client.get(
        "/api/v1/groups/", headers={"Authorization": "Bearer %s" % bob_tok}
    ).json()["groups"]
    assert {g["name"] for g in alice_groups} == {"g1", "g2"}
    assert [g["name"] for g in bob_groups] == ["g1"]


def test_create_group(client, session):
    alice, tok, _ = auth_helper(client, session, "alice")
    resp = client.post(
        "/api/v1/groups/",
        json={"name": "testgroup"},
        headers={"Authorization": "Bearer %s" % tok},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data


def test_add_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    info = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert bob.id in info["members"]


def test_remove_member_leaves_group_intact(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    info = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert bob.id not in info["members"]
    assert carol.id in info["members"]


def test_non_creator_cannot_add_or_remove_other_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert (
        client.post(
            "/api/v1/groups/%d/members" % group["id"],
            json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
            headers={"Authorization": "Bearer %s" % bob_tok},
        ).status_code
        == HTTPStatus.FORBIDDEN
    )
    assert (
        client.request(
            "DELETE",
            "/api/v1/groups/%d/members/%d" % (group["id"], carol.id),
            json={"skdm_ciphertexts": {}},
            headers={"Authorization": "Bearer %s" % bob_tok},
        ).status_code
        == HTTPStatus.FORBIDDEN
    )


def test_member_can_leave_group(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT
    info = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert bob.id not in info["members"]


def test_creator_leaving_transfers_ownership(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], alice.id),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # bob (lowest user_id among remaining) should now be able to add members
    dave, _, _ = auth_helper(client, session, "dave")
    resp = client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": dave.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT


def test_send_and_receive_group_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    send = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"group_ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert send.status_code == 201
    assert "id" in send.json()

    msgs = client.get(
        "/api/v1/groups/%d/messages" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()
    assert len(msgs) == 1


def test_non_member_cannot_send(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    _, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == 403


def test_revoke_group_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/messages/%d" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT


def test_group_deleted_when_member_count_drops_to_one(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_non_sender_cannot_revoke_group_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/messages/%d" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_group_message_receipt_removes_message_for_last_recipient(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/messages/%d/receipt" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT
    msgs = client.get(
        "/api/v1/groups/%d/messages" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()
    assert all(m["id"] != msg["id"] for m in msgs)


def test_fetch_skdms(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    skdm_b64 = base64.b64encode(b"skdm").decode()
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": skdm_b64},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.OK
    assert len(resp.json()["skdm_ciphertexts"]) == 1
    assert resp.json()["skdm_ciphertexts"][0]["ciphertext"] == skdm_b64
    assert resp.json()["skdm_ciphertexts"][0]["epoch"] == 1


def test_add_member_with_skdm_delivers_to_new_member(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": base64.b64encode(b"alice_sk_for_bob").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.OK
    assert len(resp.json()["skdm_ciphertexts"]) == 1
    assert resp.json()["skdm_ciphertexts"][0]["ciphertext"] == base64.b64encode(b"alice_sk_for_bob").decode()
    assert resp.json()["skdm_ciphertexts"][0]["epoch"] == 1


def test_epoch_increments_on_add_and_remove(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    epoch0 = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch1 = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], carol.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch3 = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    # add_member calls store_skdms which increments epoch
    assert epoch1 == epoch0 + 1
    # second add (+1) then remove (+1) = epoch0 + 3
    assert epoch3 == epoch0 + 3


def test_forced_removal_replaces_skdms_with_creator_supplied_keys(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # Consume the add_member SKDM so we can store a fresh stale one
    client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    )
    # Store stale SKDM for carol that should be purged on removal
    client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {str(carol.id): base64.b64encode(b"stale").decode()}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # Creator force-removes bob and supplies fresh re-keyed SKDM for carol
    fresh_carol_key = base64.b64encode(b"fresh").decode()
    resp = client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {str(carol.id): fresh_carol_key}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT
    # Carol should see only the new key, not the stale one
    carol_skdms = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    ).json()["skdm_ciphertexts"]
    assert len(carol_skdms) == 1
    assert carol_skdms[0]["ciphertext"] == fresh_carol_key
    # The new SKDM should carry the post-removal epoch
    group_epoch = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    assert carol_skdms[0]["epoch"] == group_epoch


def test_forced_removal_without_skdms_leaves_no_pending_keys(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # Consume the add_member SKDM so we can store a fresh one to verify purge
    client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    )
    # Store SKDM for carol — should be purged even if creator sends no new keys
    client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {str(carol.id): base64.b64encode(b"old").decode()}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    carol_skdms = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    ).json()["skdm_ciphertexts"]
    assert carol_skdms == []


def test_voluntary_leave_purges_stale_skdms(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # Consume the add_member SKDM so we can store a fresh one to verify purge
    client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    )
    # Store a pre-leave SKDM for carol — epoch 0
    client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {str(carol.id): base64.b64encode(b"sk").decode()}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    # Bob leaves voluntarily — epoch advances, stale SKDM should be purged
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    carol_skdms = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    ).json()["skdm_ciphertexts"]
    assert carol_skdms == []


def test_get_epoch_returns_current_epoch(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.OK
    # two add_member calls each invoke store_skdms (+1 each)
    assert resp.json()["epoch"] == 2

    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.json()["epoch"] == 3


def test_unauthenticated_group_requests_rejected(client, session):
    assert client.get("/api/v1/groups/").status_code == HTTPStatus.FORBIDDEN
    assert client.post("/api/v1/groups/", json={"name": "g"}).status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/groups/1").status_code == HTTPStatus.FORBIDDEN
    assert client.post("/api/v1/groups/1/members", json={}).status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/groups/1/messages").status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/v1/groups/1/skdm").status_code == HTTPStatus.FORBIDDEN


def test_non_member_cannot_access_group_info(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    _, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_add_member_empty_skdm_rejected(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_send_skdm_increments_epoch(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch_before = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {str(bob.id): base64.b64encode(b"key").decode()}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch_after = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    assert epoch_after == epoch_before + 1


def test_send_skdm_empty_dict_rejected(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.post(
        "/api/v1/groups/%d/skdm" % group["id"],
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_group_message_receipt_by_non_recipient_is_noop(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    # carol receipts the message — should not delete it since bob hasn't receipted yet
    client.post(
        "/api/v1/groups/%d/messages/%d/receipt" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % carol_tok},
    )
    msgs = client.get(
        "/api/v1/groups/%d/messages" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()
    assert any(m["id"] == msg["id"] for m in msgs)


def test_sender_does_not_see_own_group_message(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msgs = client.get(
        "/api/v1/groups/%d/messages" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    assert msgs == []


def test_get_group_info_not_found(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    resp = client.get(
        "/api/v1/groups/9999",
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_send_group_message_returns_id(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert set(data.keys()) == {"id"}
    assert isinstance(data["id"], int)


def test_add_member_increments_epoch(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    epoch_before = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch_after = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    assert epoch_after == epoch_before + 1


def test_remove_member_increments_epoch_without_skdms(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, _, _ = auth_helper(client, session, "bob")
    carol, _, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch_before = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], bob.id),
        json={"skdm_ciphertexts": {}},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    epoch_after = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()["epoch"]
    assert epoch_after == epoch_before + 1


def test_group_dissolved_when_only_one_member_remains(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.request(
        "DELETE",
        "/api/v1/groups/%d/members/%d" % (group["id"], alice.id),
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    resp = client.get(
        "/api/v1/groups/%d" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_non_member_cannot_fetch_skdms(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    _, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    resp = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    assert resp.status_code == HTTPStatus.FORBIDDEN


def test_fetch_skdms_is_consume_on_read(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": base64.b64encode(b"key").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    first = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()["skdm_ciphertexts"]
    second = client.get(
        "/api/v1/groups/%d/skdm" % group["id"],
        headers={"Authorization": "Bearer %s" % bob_tok},
    ).json()["skdm_ciphertexts"]
    assert len(first) == 1
    assert second == []


def test_group_message_receipt_removes_message_only_when_all_received(client, session):
    alice, alice_tok, _ = auth_helper(client, session, "alice")
    bob, bob_tok, _ = auth_helper(client, session, "bob")
    carol, carol_tok, _ = auth_helper(client, session, "carol")
    group = client.post(
        "/api/v1/groups/",
        json={"name": "g"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": bob.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    client.post(
        "/api/v1/groups/%d/members" % group["id"],
        json={"user_id": carol.id, "skdm_ciphertext": "AAAA"},
        headers={"Authorization": "Bearer %s" % alice_tok},
    )
    msg = client.post(
        "/api/v1/groups/%d/messages" % group["id"],
        json={"epoch": 0, "ciphertext": base64.b64encode(b"ct").decode()},
        headers={"Authorization": "Bearer %s" % alice_tok},
    ).json()
    client.post(
        "/api/v1/groups/%d/messages/%d/receipt" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % bob_tok},
    )
    # carol has not receipted — message still visible to carol
    assert any(
        m["id"] == msg["id"]
        for m in client.get(
            "/api/v1/groups/%d/messages" % group["id"],
            headers={"Authorization": "Bearer %s" % carol_tok},
        ).json()
    )
    client.post(
        "/api/v1/groups/%d/messages/%d/receipt" % (group["id"], msg["id"]),
        headers={"Authorization": "Bearer %s" % carol_tok},
    )
    # all receipted — message gone for everyone
    assert client.get(
        "/api/v1/groups/%d/messages" % group["id"],
        headers={"Authorization": "Bearer %s" % carol_tok},
    ).json() == []
