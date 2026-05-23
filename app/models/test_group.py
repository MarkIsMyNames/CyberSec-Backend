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


def test_get_groups_for_user(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    g1 = groups.create_group("g1", creator_id=alice.id)
    g2 = groups.create_group("g2", creator_id=alice.id)
    groups.add_member(g1.id, alice.id, bob.id)
    alice_groups = groups.get_groups_for_user(alice.id)
    bob_groups = groups.get_groups_for_user(bob.id)
    assert {g.id for g in alice_groups} == {g1.id, g2.id}
    assert [g.id for g in bob_groups] == [g1.id]


def test_get_groups_for_user_returns_empty_when_no_groups(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    assert groups.get_groups_for_user(alice.id) == []


def test_store_and_fetch_skdm(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.store_skdms(group.id, {bob.id: b"skdm_enc"})
    skdms = groups.pop_skdms_for_user(bob.id, group.id)
    assert len(skdms) == 1
    epoch, ciphertext = skdms[0]
    assert epoch == 0
    assert ciphertext == b"skdm_enc"


def test_store_group_message_and_revoke(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    msg = groups.store_group_message(group.id, alice.id, 0, b"\1")
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
    msg = groups.store_group_message(group.id, alice.id, 0, b"\1")
    assert groups.revoke_group_message(msg.id, bob.id) is False
    assert len(groups.get_group_messages(group.id)) == 1


def test_sender_does_not_receive_own_group_message(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.store_group_message(group.id, alice.id, 0, b"\1")
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
    msg = groups.store_group_message(group.id, alice.id, 0, b"\1")
    groups.record_group_receipt(msg.id, bob.id)
    assert len(groups.get_group_messages(group.id)) == 1
    groups.record_group_receipt(msg.id, carol.id)
    assert groups.get_group_messages(group.id) == []


def test_revoke_group_message_not_found_returns_false(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    assert groups.revoke_group_message(9999, alice.id) is False


def test_epoch_does_not_increment_on_add(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 0


def test_epoch_increments_on_forced_removal(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.remove_member(group.id, alice.id, bob.id)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 1


def test_epoch_increments_on_voluntary_leave(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.remove_member(group.id, bob.id, bob.id)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 1


def test_skdm_epoch_matches_group_epoch_at_store_time(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    dave = users.create_user("dave", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.add_member(group.id, alice.id, dave.id)
    # Force a removal to bump epoch to 1
    groups.remove_member(group.id, alice.id, dave.id)
    groups.store_skdms(group.id, {bob.id: b"fresh_key"})
    skdms = groups.pop_skdms_for_user(bob.id, group.id)
    assert len(skdms) == 1
    epoch, _ = skdms[0]
    assert epoch == 1


def test_forced_removal_purges_pending_skdms(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.store_skdms(group.id, {bob.id: b"stale_key", carol.id: b"stale_key_carol"})
    groups.remove_member(group.id, alice.id, bob.id)
    # All SKDMs purged — including carol's stale entry
    assert groups.pop_skdms_for_user(carol.id, group.id) == []


def test_voluntary_leave_purges_stale_skdms(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.store_skdms(group.id, {carol.id: b"key_for_carol"})
    groups.remove_member(group.id, bob.id, bob.id)
    assert groups.pop_skdms_for_user(carol.id, group.id) == []


def test_forced_removal_stores_supplied_skdms_at_new_epoch(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.remove_member(group.id, alice.id, bob.id, {carol.id: b"fresh_key_for_carol"})
    skdms = groups.pop_skdms_for_user(carol.id, group.id)
    assert len(skdms) == 1
    epoch, ciphertext = skdms[0]
    assert epoch == 1
    assert ciphertext == b"fresh_key_for_carol"


def test_forced_removal_without_skdms_leaves_no_pending_keys(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.store_skdms(group.id, {carol.id: b"stale"})
    groups.remove_member(group.id, alice.id, bob.id)
    assert groups.pop_skdms_for_user(carol.id, group.id) == []


def test_pop_skdms_is_consume_on_read(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.store_skdms(group.id, {bob.id: b"sk"})
    assert len(groups.pop_skdms_for_user(bob.id, group.id)) == 1
    assert groups.pop_skdms_for_user(bob.id, group.id) == []


def test_remove_nonmember_is_noop(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    dave = users.create_user("dave", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.remove_member(group.id, alice.id, dave.id)
    assert groups.get_group(group.id) is not None


def test_group_created_with_epoch_zero(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    assert group.epoch == 0


def test_store_skdms_raises_for_nonexistent_group(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    with pytest.raises(ValueError):
        groups.store_skdms(9999, {alice.id: b"sk"})


def test_record_group_receipt_noop_for_nonrecipient(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    dave = users.create_user("dave", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    msg = groups.store_group_message(group.id, alice.id, 0, b"\1")
    # dave is not a recipient — calling record_group_receipt should not crash
    groups.record_group_receipt(msg.id, dave.id)
    # message must still be present because bob has not acknowledged
    assert len(groups.get_group_messages(group.id)) == 1


def test_store_group_message_receipt_list_is_atomic(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    msg = groups.store_group_message(group.id, alice.id, 0, b"\1")
    # Exactly bob and carol receive a receipt; alice (sender) must not
    groups.record_group_receipt(msg.id, bob.id)
    assert len(groups.get_group_messages(group.id)) == 1  # carol hasn't acked
    groups.record_group_receipt(msg.id, carol.id)
    assert groups.get_group_messages(group.id) == []  # all acked — deleted


def test_pop_skdms_discards_stale_epochs(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"t")
    bob = users.create_user("bob", "aa", "bb", b"t")
    carol = users.create_user("carol", "aa", "bb", b"t")
    dave = users.create_user("dave", "aa", "bb", b"t")
    group = groups.create_group("g", creator_id=alice.id)
    groups.add_member(group.id, alice.id, bob.id)
    groups.add_member(group.id, alice.id, carol.id)
    groups.add_member(group.id, alice.id, dave.id)
    # Store a stale SKDM for bob at epoch 0
    groups.store_skdms(group.id, {bob.id: b"stale_key"})
    # Force a removal to bump epoch to 1, purging the stale SKDM
    groups.remove_member(group.id, alice.id, dave.id)
    # Store a fresh SKDM for bob at epoch 1
    groups.store_skdms(group.id, {bob.id: b"fresh_key"})
    results = groups.pop_skdms_for_user(bob.id, group.id)
    assert len(results) == 1
    epoch, ciphertext = results[0]
    assert epoch == 1
    assert ciphertext == b"fresh_key"
    # All rows consumed
    assert groups.pop_skdms_for_user(bob.id, group.id) == []
