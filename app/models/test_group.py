import hashlib
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


def test_non_creator_cannot_add_or_remove_member(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    with pytest.raises(PermissionError):
        groups.add_member(group.id, bob.id, carol.id)
    with pytest.raises(PermissionError):
        groups.remove_member(group.id, bob.id, alice.id)


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
    raw_token = b"group_revoke"
    token_hash = hashlib.sha256(raw_token).digest()
    msg = groups.store_group_message(
        group.id, ciphertext=b"gciphertext", revocation_token_hash=token_hash
    )
    assert len(groups.get_group_messages(group.id)) == 1
    assert groups.revoke_group_message(msg.id, raw_token) is True
    assert groups.get_group_messages(group.id) == []
