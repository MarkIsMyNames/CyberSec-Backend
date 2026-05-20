import pytest

from app.repositories.user import SQLUserRepository


def test_create_and_fetch_user(session):
    repo = SQLUserRepository(session)
    user = repo.create_user("alice", "hashed_pw", b"enc_totp")
    assert user.id is not None
    assert user.username == "alice"

    fetched = repo.get_user_by_username("alice")
    assert fetched is not None
    assert fetched.id == user.id

    by_id = repo.get_user_by_id(user.id)
    assert by_id is not None
    assert by_id.username == "alice"


def test_duplicate_username_raises(session):
    repo = SQLUserRepository(session)
    repo.create_user("bob", "hash1", b"totp1")
    with pytest.raises(Exception):
        repo.create_user("bob", "hash2", b"totp2")


def test_get_nonexistent_user_returns_none(session):
    repo = SQLUserRepository(session)
    assert repo.get_user_by_username("nobody") is None
    assert repo.get_user_by_id(9999) is None
