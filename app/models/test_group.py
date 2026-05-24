import pytest

from app.repositories.group import SQLGroupRepository
from app.repositories.user import SQLUserRepository


def test_creator_can_add_and_remove_members(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    assert alice in groups.get_members(group.id)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    assert {alice, bob, carol} == set(groups.get_members(group.id))
    groups.remove_member(group.id, alice, bob)
    assert bob not in groups.get_members(group.id)


def test_non_creator_cannot_add_or_remove_other_member(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    with pytest.raises(PermissionError):
        groups.add_member(group.id, bob, carol, b"skdm")
    with pytest.raises(PermissionError):
        groups.remove_member(group.id, bob, carol)


def test_member_can_leave_group(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.remove_member(group.id, bob, bob)
    assert bob not in groups.get_members(group.id)
    assert alice in groups.get_members(group.id)


def test_creator_leaving_transfers_ownership(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.remove_member(group.id, alice, alice)
    assert alice not in groups.get_members(group.id)
    # new creator (lowest user_id among remaining) can now add members
    dave = users.create_user("dave", "aa", b"bb", b"t")
    new_creator_id = min(bob, carol)
    groups.add_member(group.id, new_creator_id, dave, b"skdm")
    assert dave in groups.get_members(group.id)


def test_group_deleted_when_membership_drops_to_one(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.remove_member(group.id, alice, bob)
    assert groups.get_group(group.id) is None


def test_get_groups_for_user(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    g1 = groups.create_group("g1", creator_id=alice)
    g2 = groups.create_group("g2", creator_id=alice)
    groups.add_member(g1.id, alice, bob, b"skdm")
    alice_groups = groups.get_groups_for_user(alice)
    bob_groups = groups.get_groups_for_user(bob)
    assert {g.id for g in alice_groups} == {g1.id, g2.id}
    assert [g.id for g in bob_groups] == [g1.id]


def test_get_groups_for_user_returns_empty_when_no_groups(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    assert groups.get_groups_for_user(alice) == []


def test_store_and_fetch_skdm(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.pop_skdms_for_user(bob, group.id)  # drain add_member SKDM
    groups.store_skdms(group.id, {bob: b"skdm_enc"})
    skdms = groups.pop_skdms_for_user(bob, group.id)
    assert len(skdms) == 1
    epoch, ciphertext = skdms[0]
    assert epoch == 2
    assert ciphertext == b"skdm_enc"


def test_store_group_message_and_revoke(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    msg = groups.store_group_message(group.id, alice, 0, b"\1")
    assert len(groups.get_group_messages(group.id, bob)) == 1
    assert groups.revoke_group_message(msg.id, alice) is True
    assert groups.get_group_messages(group.id, bob) == []


def test_non_sender_cannot_revoke_group_message(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    msg = groups.store_group_message(group.id, alice, 0, b"\1")
    assert groups.revoke_group_message(msg.id, bob) is False
    assert len(groups.get_group_messages(group.id, bob)) == 1


def test_sender_does_not_receive_own_group_message(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.store_group_message(group.id, alice, 0, b"\1")
    msgs = groups.get_group_messages(group.id, bob)
    # Bob's ack is the last receipt (alice has none), so the message is deleted
    groups.record_group_receipt(msgs[0].id, bob)
    assert groups.get_group_messages(group.id, bob) == []


def test_record_group_receipt_deletes_message_when_all_acknowledged(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    msg = groups.store_group_message(group.id, alice, 0, b"\1")
    groups.record_group_receipt(msg.id, bob)
    assert len(groups.get_group_messages(group.id, carol)) == 1
    groups.record_group_receipt(msg.id, carol)
    assert groups.get_group_messages(group.id, carol) == []


def test_revoke_group_message_not_found_returns_false(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    assert groups.revoke_group_message(9999, alice) is False


def test_epoch_increments_on_add(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 1


def test_epoch_increments_on_forced_removal(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.remove_member(group.id, alice, bob)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 3


def test_epoch_increments_on_voluntary_leave(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.remove_member(group.id, bob, bob)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 3


def test_skdm_epoch_matches_group_epoch_at_store_time(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    dave = users.create_user("dave", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.add_member(group.id, alice, dave, b"skdm")
    # add_member x3 bumps epoch to 3; remove_member bumps to 4; store_skdms bumps to 5
    groups.remove_member(group.id, alice, dave)
    groups.store_skdms(group.id, {bob: b"fresh_key"})
    skdms = groups.pop_skdms_for_user(bob, group.id)
    assert len(skdms) == 1
    epoch, _ = skdms[0]
    assert epoch == 5


def test_forced_removal_purges_pending_skdms(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.store_skdms(group.id, {bob: b"stale_key", carol: b"stale_key_carol"})
    groups.remove_member(group.id, alice, bob)
    # All SKDMs purged — including carol's stale entry
    assert groups.pop_skdms_for_user(carol, group.id) == []


def test_voluntary_leave_purges_stale_skdms(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.store_skdms(group.id, {carol: b"key_for_carol"})
    groups.remove_member(group.id, bob, bob)
    assert groups.pop_skdms_for_user(carol, group.id) == []


def test_forced_removal_stores_supplied_skdms_at_new_epoch(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    # add_member x2 bumps epoch to 2; remove_member with SKDMs bumps to 3
    groups.remove_member(group.id, alice, bob, {carol: b"fresh_key_for_carol"})
    skdms = groups.pop_skdms_for_user(carol, group.id)
    assert len(skdms) == 1
    epoch, ciphertext = skdms[0]
    assert epoch == 3
    assert ciphertext == b"fresh_key_for_carol"


def test_forced_removal_without_skdms_leaves_no_pending_keys(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.store_skdms(group.id, {carol: b"stale"})
    groups.remove_member(group.id, alice, bob)
    assert groups.pop_skdms_for_user(carol, group.id) == []


def test_pop_skdms_is_consume_on_read(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.pop_skdms_for_user(bob, group.id)  # drain add_member SKDM
    groups.store_skdms(group.id, {bob: b"sk"})
    assert len(groups.pop_skdms_for_user(bob, group.id)) == 1
    assert groups.pop_skdms_for_user(bob, group.id) == []


def test_remove_nonmember_is_noop(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    dave = users.create_user("dave", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.remove_member(group.id, alice, dave)
    assert groups.get_group(group.id) is not None


def test_group_created_with_epoch_zero(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    assert group.epoch == 0


def test_store_skdms_raises_for_nonexistent_group(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    with pytest.raises(ValueError):
        groups.store_skdms(9999, {alice: b"sk"})


def test_record_group_receipt_noop_for_nonrecipient(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    dave = users.create_user("dave", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    msg = groups.store_group_message(group.id, alice, 0, b"\1")
    # dave is not a recipient — calling record_group_receipt should not crash
    groups.record_group_receipt(msg.id, dave)
    # message must still be present because bob has not acknowledged
    assert len(groups.get_group_messages(group.id, bob)) == 1


def test_store_group_message_receipt_list_is_atomic(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    msg = groups.store_group_message(group.id, alice, 0, b"\1")
    # Exactly bob and carol receive a receipt; alice (sender) must not
    groups.record_group_receipt(msg.id, bob)
    assert len(groups.get_group_messages(group.id, carol)) == 1  # carol hasn't acked
    groups.record_group_receipt(msg.id, carol)
    assert groups.get_group_messages(group.id, carol) == []  # all acked — deleted


def test_pop_skdms_discards_stale_epochs(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    dave = users.create_user("dave", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.add_member(group.id, alice, dave, b"skdm")
    # add_member x3 bumps epoch to 3; store_skdms bumps to 4 — stale key for bob
    groups.store_skdms(group.id, {bob: b"stale_key"})
    # remove_member bumps epoch to 5, purging all SKDMs including stale ones
    groups.remove_member(group.id, alice, dave)
    # store_skdms bumps epoch to 6 — fresh key for bob
    groups.store_skdms(group.id, {bob: b"fresh_key"})
    results = groups.pop_skdms_for_user(bob, group.id)
    assert len(results) == 1
    epoch, ciphertext = results[0]
    assert epoch == 6
    assert ciphertext == b"fresh_key"
    # All rows consumed
    assert groups.pop_skdms_for_user(bob, group.id) == []


def test_remove_member_noop_does_not_change_epoch(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    dave = users.create_user("dave", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.remove_member(group.id, alice, dave)
    fetched = groups.get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 0


def test_group_deleted_when_last_member_leaves(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    # removing bob leaves alice alone — group dissolves
    groups.remove_member(group.id, alice, bob)
    assert groups.get_group(group.id) is None


def test_store_skdms_increments_epoch(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    g1 = groups.get_group(group.id)
    assert g1 is not None
    assert g1.epoch == 1
    groups.store_skdms(group.id, {bob: b"key"})
    g2 = groups.get_group(group.id)
    assert g2 is not None
    assert g2.epoch == 2
    groups.store_skdms(group.id, {bob: b"key2"})
    g3 = groups.get_group(group.id)
    assert g3 is not None
    assert g3.epoch == 3


def test_is_member_returns_correct_values(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    assert groups.is_member(group.id, alice) is True
    assert groups.is_member(group.id, bob) is False
    groups.add_member(group.id, alice, bob, b"skdm")
    assert groups.is_member(group.id, bob) is True


def test_get_group_messages_only_returns_messages_for_user(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.store_group_message(group.id, alice, 0, b"ct")
    assert len(groups.get_group_messages(group.id, bob)) == 1
    assert groups.get_group_messages(group.id, alice) == []


def test_forced_removal_skdms_are_at_post_removal_epoch(session):
    users = SQLUserRepository(session)
    groups = SQLGroupRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"t")
    bob = users.create_user("bob", "aa", b"bb", b"t")
    carol = users.create_user("carol", "aa", b"bb", b"t")
    group = groups.create_group("g", creator_id=alice)
    groups.add_member(group.id, alice, bob, b"skdm")
    groups.add_member(group.id, alice, carol, b"skdm")
    groups.remove_member(group.id, alice, bob, {carol: b"fresh"})
    fetched = groups.get_group(group.id)
    assert fetched is not None
    group_epoch = fetched.epoch
    skdms = groups.pop_skdms_for_user(carol, group.id)
    assert len(skdms) == 1
    assert skdms[0][0] == group_epoch
