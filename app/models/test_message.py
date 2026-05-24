from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository
import pytest
from app.config import config


def test_store_and_fetch_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    msg = msgs.store_message(
        sender_id=alice,
        recipient_id=bob,
        ciphertext=b"ciphertext",
        ratchet_header_enc=b"header",
    )
    assert msg is not None
    assert [m.id for m in msgs.get_messages_for_user(bob, limit=100, offset=0)] == [msg]


def test_record_receipt_and_delete_when_all_received(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    msg = msgs.store_message(alice, bob, b"ct", b"hdr")
    msgs.delete_message(msg, "recipient_id", bob)
    assert msgs.get_messages_for_user(bob, limit=100, offset=0) == []


def test_revoke_message_by_sender(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    msg = msgs.store_message(alice, bob, b"ct", b"hdr")
    assert msgs.delete_message(msg, "sender_id", alice) is True
    assert msgs.get_messages_for_user(bob, limit=100, offset=0) == []


def test_revoke_by_non_sender_fails(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    msg = msgs.store_message(alice, bob, b"ct", b"hdr")
    assert msgs.delete_message(msg, "sender_id", bob) is False


def test_record_receipt_returns_true_for_valid_recipient(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    msg = msgs.store_message(alice, bob, b"ct", b"hdr")
    assert msgs.delete_message(msg, "recipient_id", bob) is True
    assert msgs.get_messages_for_user(bob, limit=100, offset=0) == []


def test_record_receipt_returns_false_for_wrong_user(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    carol = users.create_user("carol", "ee", b"ff", b"totp")
    msg = msgs.store_message(alice, bob, b"ct", b"hdr")
    assert msgs.delete_message(msg, "recipient_id", carol) is False
    assert [m.id for m in msgs.get_messages_for_user(bob, limit=100, offset=0)] == [msg]


def test_record_receipt_returns_false_for_missing_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", b"bb", b"totp")
    assert msgs.delete_message(9999, "recipient_id", bob) is False


def test_store_message_raises_on_inbox_overflow(session, monkeypatch):
    monkeypatch.setitem(config["messaging"], "inbox_max_messages", 3)
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    for _ in range(3):
        msgs.store_message(alice, bob, b"ct", b"hdr")
    with pytest.raises(OverflowError):
        msgs.store_message(alice, bob, b"ct", b"hdr")


def test_pagination_returns_messages_in_order(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", b"bb", b"totp")
    bob = users.create_user("bob", "cc", b"dd", b"totp")
    ids = [msgs.store_message(alice, bob, b"ct%d" % i, b"hdr") for i in range(5)]
    page1 = [m.id for m in msgs.get_messages_for_user(bob, limit=3, offset=0)]
    page2 = [m.id for m in msgs.get_messages_for_user(bob, limit=3, offset=3)]
    assert page1 == ids[:3]
    assert page2 == ids[3:]
