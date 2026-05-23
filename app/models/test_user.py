import pytest

from app.repositories.user import SQLUserRepository


def test_create_and_fetch_user(session):
    repo = SQLUserRepository(session)
    user_id = repo.create_user("alice", "aa", "bb", b"enc_totp")
    assert user_id is not None

    fetched = repo.get_user_by_username("alice")
    assert fetched is not None
    assert fetched.id == user_id

    by_id = repo.get_user_by_id(user_id)
    assert by_id is not None
    assert by_id.username == "alice"


def test_duplicate_username_raises(session):
    repo = SQLUserRepository(session)
    repo.create_user("bob", "aa", "bb", b"totp1")
    with pytest.raises(Exception):
        repo.create_user("bob", "aa", "bb", b"totp2")


def test_get_nonexistent_user_returns_none(session):
    repo = SQLUserRepository(session)
    assert repo.get_user_by_username("nobody") is None
    assert repo.get_user_by_id(9999) is None


def test_block_and_check_refresh_token(session):
    repo = SQLUserRepository(session)
    jti_hash = b"deadbeef" * 4
    assert repo.is_refresh_token_blocked(jti_hash) is False
    repo.block_refresh_token(jti_hash, expires_at=9999999999)
    assert repo.is_refresh_token_blocked(jti_hash) is True


def test_different_jti_hashes_are_independent(session):
    repo = SQLUserRepository(session)
    repo.block_refresh_token(b"hash_a" * 4, expires_at=9999999999)
    assert repo.is_refresh_token_blocked(b"hash_b" * 4) is False
