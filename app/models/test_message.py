import hashlib

from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository


def test_store_and_fetch_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    token_hash = hashlib.sha256(b"revoke_token_1").digest()
    msg = msgs.store_message(
        recipient_id=bob.id,
        ciphertext=b"ciphertext",
        ratchet_header_enc=b"header",
        revocation_token_hash=token_hash,
    )
    assert msg.id is not None
    assert msgs.get_messages_for_user(bob.id) == [msg]


def test_record_receipt_and_delete_when_all_received(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    token_hash = hashlib.sha256(b"tok").digest()
    msg = msgs.store_message(bob.id, b"ct", b"hdr", token_hash)
    msgs.record_receipt(msg.id, bob.id)
    assert msgs.get_messages_for_user(bob.id) == []


def test_revoke_message_by_token(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    raw_token = b"secret_revoke_token"
    token_hash = hashlib.sha256(raw_token).digest()
    msg = msgs.store_message(bob.id, b"ct", b"hdr", token_hash)
    assert msgs.revoke_message(msg.id, raw_token) is True
    assert msgs.get_messages_for_user(bob.id) == []


def test_revoke_with_wrong_token_fails(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    token_hash = hashlib.sha256(b"correct").digest()
    msg = msgs.store_message(bob.id, b"ct", b"hdr", token_hash)
    assert msgs.revoke_message(msg.id, b"wrong") is False


def test_get_message_for_recipient_returns_message(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    msg = msgs.store_message(bob.id, b"ct", b"hdr", hashlib.sha256(b"tok").digest())
    assert msgs.get_message_for_recipient(msg.id, bob.id) == msg


def test_get_message_for_recipient_returns_none_for_wrong_user(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    alice = users.create_user("alice", "aa", "bb", b"totp")
    msg = msgs.store_message(bob.id, b"ct", b"hdr", hashlib.sha256(b"tok").digest())
    assert msgs.get_message_for_recipient(msg.id, alice.id) is None


def test_get_message_for_recipient_returns_none_for_missing_id(session):
    users = SQLUserRepository(session)
    msgs = SQLMessageRepository(session)
    bob = users.create_user("bob", "aa", "bb", b"totp")
    assert msgs.get_message_for_recipient(9999, bob.id) is None
