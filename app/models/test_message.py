from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository


def test_store_and_fetch_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    msg = msgs.store_message(
        sender_id=alice.id,
        recipient_id=bob.id,
        ciphertext=b"ciphertext",
        ratchet_header_enc=b"header",
    )
    assert msg.id is not None
    assert msgs.get_messages_for_user(bob.id, limit=100, offset=0) == [msg]


def test_record_receipt_and_delete_when_all_received(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    msg = msgs.store_message(alice.id, bob.id, b"ct", b"hdr")
    msgs.record_receipt(msg.id, bob.id)
    assert msgs.get_messages_for_user(bob.id, limit=100, offset=0) == []


def test_revoke_message_by_sender(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    msg = msgs.store_message(alice.id, bob.id, b"ct", b"hdr")
    assert msgs.revoke_message(msg.id, alice.id) is True
    assert msgs.get_messages_for_user(bob.id, limit=100, offset=0) == []


def test_revoke_by_non_sender_fails(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    msg = msgs.store_message(alice.id, bob.id, b"ct", b"hdr")
    assert msgs.revoke_message(msg.id, bob.id) is False


def test_record_receipt_returns_true_for_valid_recipient(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    msg = msgs.store_message(alice.id, bob.id, b"ct", b"hdr")
    assert msgs.record_receipt(msg.id, bob.id) is True
    assert msgs.get_messages_for_user(bob.id, limit=100, offset=0) == []


def test_record_receipt_returns_false_for_wrong_user(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    alice = users.create_user("alice", "aa", "bb", b"totp")
    bob = users.create_user("bob", "cc", "dd", b"totp")
    carol = users.create_user("carol", "ee", "ff", b"totp")
    msg = msgs.store_message(alice.id, bob.id, b"ct", b"hdr")
    assert msgs.record_receipt(msg.id, carol.id) is False
    assert msgs.get_messages_for_user(bob.id, limit=100, offset=0) == [msg]


def test_record_receipt_returns_false_for_missing_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    assert msgs.record_receipt(9999, bob.id) is False
