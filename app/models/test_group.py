import pytest

from app.repositories.group import SQLGroupRepository
from app.repositories.user import SQLUserRepository


def test_creator_can_add_and_remove_members(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    assert alice.id in groups.get_members(group.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    assert {alice.id, bob.id, carol.id} == set(groups.get_members(group.id))
    groups.remove_member(group.id, alice.id, bob.id)
    assert bob.id not in groups.get_members(group.id)


def test_non_creator_cannot_add_or_remove_other_member(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    with pytest.raises(PermissionError):
        groups.add_member(group.id, bob.id, carol.id)
    with pytest.raises(PermissionError):
        groups.remove_member(group.id, bob.id, carol.id)


def test_member_can_leave_group(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.remove_member(group.id, bob.id, bob.id)
    assert bob.id not in groups.get_members(group.id)
    assert alice.id in groups.get_members(group.id)


def test_creator_leaving_transfers_ownership(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.remove_member(group.id, alice.id, alice.id)
    assert alice.id not in groups.get_members(group.id)
    # new creator (lowest user_id among remaining) can now add members
    dave = users.create_user("dave", "aa", "bb", b"t")
    new_creator_id = min(bob.id, carol.id)
    groups.add_member(group.id, new_creator_id, dave.id)
    assert dave.id in groups.get_members(group.id)


def test_group_deleted_when_membership_drops_to_one(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.remove_member(group.id, alice.id, bob.id)
    assert groups.get_group(group.id) is None


def test_store_and_fetch_skdm(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.store_skdm(group.id, recipient_id=bob.id, skdm_ciphertext=b"skdm_enc")
    skdms = groups.get_skdms_for_user(bob.id, group.id)
    assert len(skdms) == 1
    assert skdms[0] == b"skdm_enc"


def test_store_group_message_and_revoke(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    msg = groups.store_group_message(group.id, alice.id, b"gciphertext")
    assert len(groups.get_group_messages(group.id)) == 1
    assert groups.revoke_group_message(msg.id, alice.id) is True
    assert groups.get_group_messages(group.id) == []


def test_non_sender_cannot_revoke_group_message(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    msg = groups.store_group_message(group.id, alice.id, b"gciphertext")
    assert groups.revoke_group_message(msg.id, bob.id) is False
    assert len(groups.get_group_messages(group.id)) == 1


def test_sender_does_not_receive_own_group_message(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.store_group_message(group.id, alice.id, b"ct")
    msgs = groups.get_group_messages(group.id)
    # Bob's ack is the last receipt (alice has none), so the message is deleted
    groups.record_group_receipt(msgs[0].id, bob.id)
    assert groups.get_group_messages(group.id) == []


def test_record_group_receipt_deletes_message_when_all_acknowledged(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    msg = groups.store_group_message(group.id, alice.id, b"ct")
    groups.record_group_receipt(msg.id, bob.id)
    assert len(groups.get_group_messages(group.id)) == 1
    groups.record_group_receipt(msg.id, carol.id)
    assert groups.get_group_messages(group.id) == []


def test_revoke_group_message_not_found_returns_false(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    assert groups.revoke_group_message(9999, alice.id) is False
