import base64
import hashlib
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
import psycopg2.errors

from app.security_tests.test_helper import auth_helper

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


def test_concurrent_add_member_while_user_deleted(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_amd1", "s", b"v", b"t")
        target = users.create_user("target_amd1", "s", b"v", b"t")
        group = SQLGroupRepository(setup_sess).create_group("g", creator_id=alice)

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def add() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).add_member(group.id, alice, target, b"skdm")
        except (SQLAlchemyError, ValueError):
            pass
        except Exception as exc:
            with lock:
                errors.append(exc)

    def delete() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLUserRepository(sess).delete_user(target)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(add)
        f2 = ex.submit(delete)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "unexpected errors: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        user_gone = SQLUserRepository(check_sess).get_user_by_id(target) is None
        still_member = SQLGroupRepository(check_sess).is_member(group.id, target)
    assert user_gone, "target user must have been deleted"
    assert not still_member, "deleted user must not remain a group member"


def test_concurrent_remove_member_same_group_consistent_creator(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_rmc1", "s", b"v", b"t")
        bob = users.create_user("bob_rmc1", "s", b"v", b"t")
        carol = users.create_user("carol_rmc1", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")
        repo.add_member(group.id, alice, carol, b"skdm")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    def kick_bob() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).remove_member(group.id, alice, bob)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    def bob_leaves() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).remove_member(group.id, bob, bob)
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(kick_bob)
        f2 = ex.submit(bob_leaves)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "unexpected errors: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        repo = SQLGroupRepository(check_sess)
        fetched = repo.get_group(group.id)
        members = repo.get_members(group.id)
    assert fetched is not None, "group must still exist (alice + carol remain)"
    assert fetched.creator_id == alice, "alice must still be creator"
    assert bob not in members, "bob must have been removed"
    assert carol in members, "carol must still be a member"


def test_concurrent_add_and_remove_skdm_epoch_no_orphan(concurrent_db):
    with Session(concurrent_db, expire_on_commit=False) as setup_sess:
        users = SQLUserRepository(setup_sess)
        alice = users.create_user("alice_skdm2", "s", b"v", b"t")
        bob = users.create_user("bob_skdm2", "s", b"v", b"t")
        carol = users.create_user("carol_skdm2", "s", b"v", b"t")
        repo = SQLGroupRepository(setup_sess)
        group = repo.create_group("g", creator_id=alice)
        repo.add_member(group.id, alice, bob, b"skdm")

    barrier = threading.Barrier(2)
    errors: list[Exception] = []
    lock = threading.Lock()

    add_carol_errors: list[Exception] = []

    def add_carol() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).add_member(
                    group.id, alice, carol, b"skdm_carol"
                )
        except SQLAlchemyError as exc:
            with lock:
                add_carol_errors.append(exc)

    def remove_bob() -> None:
        barrier.wait()
        try:
            with Session(concurrent_db, expire_on_commit=False) as sess:
                SQLGroupRepository(sess).remove_member(
                    group.id, alice, bob, {alice: b"skdm_alice"}
                )
        except SQLAlchemyError as exc:
            with lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(add_carol)
        f2 = ex.submit(remove_bob)
        f1.result(timeout=10)
        f2.result(timeout=10)

    assert errors == [], "remove_bob must not error: %s" % errors
    with Session(concurrent_db, expire_on_commit=False) as check_sess:
        repo = SQLGroupRepository(check_sess)
        fetched = repo.get_group(group.id)
        members = repo.get_members(group.id)
    assert fetched is not None
    assert bob not in members, "bob must have been removed"
    assert fetched.epoch > 0, "epoch must have been incremented"


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


def test_concurrent_creator_and_member_delete_consistent_group(client, session):
    creator, tok_c, _ = auth_helper(client, session, "httpconcreator")
    member, tok_m, _ = auth_helper(client, session, "httpconcmember")
    _b64 = base64.b64encode(b"\x09" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "http_concgroup"},
        headers={"Authorization": "Bearer %s" % tok_c},
    ).json()
    group_id = grp_resp["id"]
    client.post(
        "/api/v1/groups/%d/members" % group_id,
        json={"user_id": member.id, "skdm_ciphertext": _b64},
        headers={"Authorization": "Bearer %s" % tok_c},
    )
    errors = []

    def _delete_creator():
        try:
            client.delete(
                "/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok_c}
            )
        except Exception as exc:
            errors.append(exc)

    def _delete_member():
        try:
            client.delete(
                "/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok_m}
            )
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_delete_creator)
    t2 = threading.Thread(target=_delete_member)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert errors == [], "no unhandled exceptions during concurrent deletes"
    repo = SQLUserRepository(session)
    grp_repo = SQLGroupRepository(session)
    creator_gone = repo.get_user_by_id(creator.id) is None
    member_gone = repo.get_user_by_id(member.id) is None
    group = grp_repo.get_group(group_id)
    if creator_gone and member_gone:
        assert group is None, "group must be deleted when all members gone"
    else:
        assert group is not None, "group must exist while a member remains"
        surviving_id = member.id if creator_gone else creator.id
        assert group.creator_id == surviving_id


def test_concurrent_double_delete_me_only_one_succeeds(client, session):
    user, access_token, _ = auth_helper(client, session, "httponcdel")
    results = []

    def _delete():
        resp = client.delete(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer %s" % access_token},
        )
        results.append(resp.status_code)

    threads = [threading.Thread(target=_delete) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert HTTPStatus.NO_CONTENT in results
    assert any(
        s in results for s in (HTTPStatus.UNAUTHORIZED, HTTPStatus.NOT_FOUND)
    ), "second delete must fail: %s" % results
    assert SQLUserRepository(session).get_user_by_id(user.id) is None


def test_delete_me_while_messages_sending_no_orphan(client, session):
    user_a, tok_a, _ = auth_helper(client, session, "httpconcenda")
    user_b, tok_b, _ = auth_helper(client, session, "httpconsendb")
    _b64 = base64.b64encode(b"\x05" * 32).decode()
    errors = []

    def _send():
        for _ in range(5):
            try:
                client.post(
                    "/api/v1/messages/",
                    json={
                        "recipient_id": user_b.id,
                        "ciphertext": _b64,
                        "ratchet_header_enc": _b64,
                    },
                    headers={"Authorization": "Bearer %s" % tok_a},
                )
            except Exception as exc:
                errors.append(exc)

    def _delete():
        time.sleep(0.05)
        client.delete("/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok_a})

    t1 = threading.Thread(target=_send)
    t2 = threading.Thread(target=_delete)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert errors == []


def test_concurrent_add_member_while_user_deleted_http(client, session):
    creator, tok_c, _ = auth_helper(client, session, "httpraceaddc")
    target, tok_t, _ = auth_helper(client, session, "httpraceaddt")
    _b64 = base64.b64encode(b"\x0a" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "http_race_add_group"},
        headers={"Authorization": "Bearer %s" % tok_c},
    ).json()
    group_id = grp_resp["id"]
    errors = []

    def _add():
        try:
            client.post(
                "/api/v1/groups/%d/members" % group_id,
                json={"user_id": target.id, "skdm_ciphertext": _b64},
                headers={"Authorization": "Bearer %s" % tok_c},
            )
        except Exception as exc:
            errors.append(exc)

    def _delete():
        try:
            client.delete(
                "/api/v1/auth/me", headers={"Authorization": "Bearer %s" % tok_t}
            )
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_add)
    t2 = threading.Thread(target=_delete)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert errors == []
    assert SQLUserRepository(session).get_user_by_id(target.id) is None
    assert not SQLGroupRepository(session).is_member(group_id, target.id)


def test_concurrent_remove_member_same_group_http(client, session):
    creator, tok_c, _ = auth_helper(client, session, "httpracerc")
    member_a, tok_a, _ = auth_helper(client, session, "httpraceremovea")
    member_b, tok_b, _ = auth_helper(client, session, "httpraceremoveb")
    _b64 = base64.b64encode(b"\x0b" * 32).decode()
    grp_resp = client.post(
        "/api/v1/groups/",
        json={"name": "http_race_rm_group"},
        headers={"Authorization": "Bearer %s" % tok_c},
    ).json()
    group_id = grp_resp["id"]
    for uid in [member_a.id, member_b.id]:
        client.post(
            "/api/v1/groups/%d/members" % group_id,
            json={"user_id": uid, "skdm_ciphertext": _b64},
            headers={"Authorization": "Bearer %s" % tok_c},
        )
    errors = []

    def _kick():
        try:
            client.delete(
                "/api/v1/groups/%d/members/%d" % (group_id, member_a.id),
                headers={"Authorization": "Bearer %s" % tok_c},
            )
        except Exception as exc:
            errors.append(exc)

    def _leave():
        try:
            client.delete(
                "/api/v1/groups/%d/members/%d" % (group_id, member_a.id),
                headers={"Authorization": "Bearer %s" % tok_a},
            )
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_kick)
    t2 = threading.Thread(target=_leave)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert errors == []
    grp_repo = SQLGroupRepository(session)
    group = grp_repo.get_group(group_id)
    assert group is not None
    assert not grp_repo.is_member(group_id, member_a.id)
    assert grp_repo.is_member(group_id, member_b.id)
    assert group.creator_id == creator.id
