import hashlib
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
import psycopg2.errors

from app.config import config
from app.database import init_db
from app.models.group import GroupMessage
from app.models.message import Message
from app.models.user import RefreshTokenBlocklist
from app.repositories.group import SQLGroupRepository
from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository
from app.session import get_engine, reset_engine


@pytest.fixture
def concurrent_db(monkeypatch):
    monkeypatch.setenv("SERVER_MASTER_SECRET", "a" * 64)
    monkeypatch.setenv(
        "JWT_SECRET_KEY", "test_jwt_secret_key_for_ci_only_not_for_production"
    )
    reset_engine()
    init_db()
    yield get_engine()
    reset_engine()


def test_concurrent_pop_one_time_prekey_no_duplicate(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        alice = SQLUserRepository(setup_sess).create_user("alice", "s", b"v", b"t")
        SQLKeyBundleRepository(setup_sess).add_one_time_prekeys(
            alice, [b"unique_key_material"]
        )

    barrier = threading.Barrier(2)
    results: list[bytes | None] = []
    lock = threading.Lock()

    def pop() -> None:
        barrier.wait()
        with Session(concurrent_db, expire_on_commit=False) as sess:
            key = SQLKeyBundleRepository(sess).pop_one_time_prekey(alice)
        with lock:
            results.append(key)

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(pop) for _ in range(2)]
        for f in futures:
            f.result()

    non_none = [r for r in results if r is not None]
    assert len(non_none) == 1, "exactly one pop should return the key"
    assert non_none[0] == b"unique_key_material"


def test_concurrent_add_member_no_duplicate(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice2", "s", b"v", b"t")
        bob = users.create_user("bob2", "s", b"v", b"t")
        group = SQLGroupRepository(setup_sess).create_group("g", creator_id=alice)

    barrier = threading.Barrier(5)
    errors: list[Exception] = []
    lock = threading.Lock()

    def add() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).add_member(group.id, alice, bob, b"skdm")
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(add) for _ in range(5)]
        for f in futures:
            f.result()

    assert errors == [], "no exceptions expected: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        members = SQLGroupRepository(check_sess).get_members(group.id)
    assert members.count(bob) == 1


def test_concurrent_remove_member_epoch_increments_correctly(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice3", "s", b"v", b"t")
        bob = users.create_user("bob3", "s", b"v", b"t")
        carol = users.create_user("carol3", "s", b"v", b"t")
        dave = users.create_user("dave3", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")
        repo.add_member(group.id, alice, dave, b"skdm")

    barrier = threading.Barrier(2)

    def remove(target_id: int) -> None:
        barrier.wait()
        with Session(concurrent_db, expire_on_commit=False) as sess:
            SQLGroupRepository(sess).remove_member(group.id, alice, target_id)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(remove, bob)
        f2 = ex.submit(remove, carol)
        f1.result()
        f2.result()

    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        fetched = SQLGroupRepository(check_sess).get_group(group.id)
    assert fetched is not None
    assert fetched.epoch == 5, (
        "each removal must increment epoch once: got %d" % fetched.epoch
    )


def test_concurrent_store_message_respects_inbox_limit(concurrent_db, monkeypatch):
    max_msgs = 5
    monkeypatch.setitem(config["messaging"], "inbox_max_messages", max_msgs)

    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        sender = users.create_user("sender_c", "s", b"v", b"t")
        recipient = users.create_user("recipient_c", "s", b"v", b"t")
        repo = SQLMessageRepository(setup_sess)
        for _ in range(max_msgs - 1):
            repo.store_message(sender, recipient, b"ct", b"hdr")

    barrier = threading.Barrier(2)
    successes: list[bool] = []
    lock = threading.Lock()

    def send() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLMessageRepository(sess).store_message(
                    sender, recipient, b"ct", b"hdr"
                )
            with lock:
                successes.append(True)
        except OverflowError:
            with lock:
                successes.append(False)

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(send) for _ in range(2)]
        for f in futures:
            f.result()

    assert successes.count(True) == 1, "exactly one send should succeed: %s" % successes

    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = (
            check_sess.scalar(
                select(func.count())
                .select_from(Message)
                .where(Message.recipient_id == recipient)
            )
            or 0
        )
    assert count == max_msgs


def test_concurrent_remove_member_no_deadlock(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_nd1", "s", b"v", b"t")
        bob = users.create_user("bob_nd1", "s", b"v", b"t")
        carol = users.create_user("carol_nd1", "s", b"v", b"t")
        dave = users.create_user("dave_nd1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")
        repo.add_member(group.id, alice, dave, b"skdm")

    errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def remove(target_id: int) -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).remove_member(group.id, alice, target_id)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(remove, bob)
        f2 = ex.submit(remove, carol)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "deadlock or unexpected error: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        members = SQLGroupRepository(check_sess).get_members(group.id)
    assert bob not in members
    assert carol not in members
    assert alice in members


def test_concurrent_send_message_and_add_member_no_deadlock(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_nd2", "s", b"v", b"t")
        bob = users.create_user("bob_nd2", "s", b"v", b"t")
        carol = users.create_user("carol_nd2", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")

    errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def send_message() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).store_group_message(group.id, alice, 0, b"ct")
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    def add_member() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).add_member(group.id, alice, carol, b"skdm")
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(send_message)
        f2 = ex.submit(add_member)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "deadlock or unexpected error: %s" % errors


def test_concurrent_remove_member_same_target_no_deadlock(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_nd3", "s", b"v", b"t")
        bob = users.create_user("bob_nd3", "s", b"v", b"t")
        carol = users.create_user("carol_nd3", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")
        initial_group = repo.get_group(group.id)
        assert initial_group is not None
        initial_epoch = initial_group.epoch

    errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def remove_bob() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).remove_member(group.id, alice, bob)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(remove_bob)
        f2 = ex.submit(remove_bob)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "deadlock or unexpected error: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        repo = SQLGroupRepository(check_sess)
        members = repo.get_members(group.id)
        fetched = repo.get_group(group.id)
    assert bob not in members
    assert fetched is not None
    assert (
        fetched.epoch == initial_epoch + 1
    ), "epoch should increment exactly once: expected %d got %d" % (
        initial_epoch + 1,
        fetched.epoch,
    )


def test_concurrent_receipt_no_double_delete(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_r1", "s", b"v", b"t")
        bob = users.create_user("bob_r1", "s", b"v", b"t")
        msg_id = SQLMessageRepository(setup_sess).store_message(
            alice, bob, b"ct", b"hdr"
        )

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def record_receipt() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLMessageRepository(sess).delete_message(msg_id, "recipient_id", bob)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(record_receipt)
        f2 = ex.submit(record_receipt)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "concurrent receipts should not raise: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = (
            check_sess.scalar(
                select(func.count()).select_from(Message).where(Message.id == msg_id)
            )
            or 0
        )
    assert count == 0


def test_concurrent_group_message_revoke_idempotent(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_gr1", "s", b"v", b"t")
        bob = users.create_user("bob_gr1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        msg = repo.store_group_message(group.id, alice, 0, b"ct")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def revoke() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).revoke_group_message(msg.id, alice)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(revoke)
        f2 = ex.submit(revoke)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "concurrent revocations should not raise: %s" % errors


def test_concurrent_refresh_token_replay_only_one_succeeds(concurrent_db):
    jti = secrets.token_hex(16)
    jti_hash = hashlib.sha256(jti.encode()).digest()
    expires_at = int(time.time()) + 3600

    successes: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def try_block() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                repo = SQLUserRepository(sess)
                if not repo.is_refresh_token_blocked(jti_hash):
                    repo.block_refresh_token(jti_hash, expires_at)
                    with lock:
                        successes.append(True)
                else:
                    with lock:
                        successes.append(False)
        except (SQLAlchemyError, psycopg2.errors.UniqueViolation):
            with lock:
                successes.append(False)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(try_block)
        f2 = ex.submit(try_block)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert successes.count(True) == 1, (
        "only one replay attempt should succeed: %s" % successes
    )
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = (
            check_sess.scalar(
                select(func.count())
                .select_from(RefreshTokenBlocklist)
                .where(RefreshTokenBlocklist.jti_hash == jti_hash)
            )
            or 0
        )
    assert count == 1, "exactly one blocklist entry must exist"


def test_concurrent_group_receipt_message_deleted_after_all_acknowledge(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_gcr1", "s", b"v", b"t")
        bob = users.create_user("bob_gcr1", "s", b"v", b"t")
        carol = users.create_user("carol_gcr1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")
        msg = repo.store_group_message(group.id, alice, 0, b"ct")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def record(user_id: int) -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).record_group_receipt(msg.id, user_id)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(record, bob)
        f2 = ex.submit(record, carol)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "concurrent receipts should not raise: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = (
            check_sess.scalar(
                select(func.count())
                .select_from(GroupMessage)
                .where(GroupMessage.id == msg.id)
            )
            or 0
        )
    assert count == 0, "message must be deleted once all recipients acknowledge"


def test_concurrent_pop_skdms_no_duplicate(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_skdm1", "s", b"v", b"t")
        bob = users.create_user("bob_skdm1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.store_skdms(group.id, {bob: b"skdm_payload"})

    barrier = threading.Barrier(2)
    results: list[list[tuple[int, bytes]]] = []
    lock = threading.Lock()

    def pop() -> None:
        barrier.wait()
        with Session(concurrent_db, expire_on_commit=False) as sess:
            skdms = SQLGroupRepository(sess).pop_skdms_for_user(bob, group.id)
        with lock:
            results.append(skdms)

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(pop) for _ in range(2)]
        for f in futures:
            f.result(timeout=10)

    non_empty = [r for r in results if r]
    assert len(non_empty) == 1, "exactly one pop should return the SKDM"
    assert non_empty[0][0][1] == b"skdm_payload"


def test_concurrent_group_messages_from_different_senders(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_gm1", "s", b"v", b"t")
        bob = users.create_user("bob_gm1", "s", b"v", b"t")
        carol = users.create_user("carol_gm1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def send(sender_id: int) -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).store_group_message(
                    group.id, sender_id, 0, b"ct"
                )
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(send, alice)
        f2 = ex.submit(send, bob)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "both sends should succeed: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = (
            check_sess.scalar(
                select(func.count())
                .select_from(GroupMessage)
                .where(GroupMessage.group_id == group.id)
            )
            or 0
        )
    assert count == 2, "both messages must be stored"


def test_concurrent_one_time_prekey_upload_no_loss(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        alice = SQLUserRepository(setup_sess).create_user("alice_opk1", "s", b"v", b"t")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def upload(batch: list[bytes]) -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLKeyBundleRepository(sess).add_one_time_prekeys(alice, batch)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(upload, [b"key_a1", b"key_a2"])
        f2 = ex.submit(upload, [b"key_b1", b"key_b2"])
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "concurrent uploads should not raise: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        count = SQLKeyBundleRepository(check_sess).count_one_time_prekeys(alice)
    assert count == 4, "all 4 uploaded keys must be stored"
