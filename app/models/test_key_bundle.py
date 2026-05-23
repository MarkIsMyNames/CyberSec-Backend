from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.user import SQLUserRepository


def test_store_and_fetch_key_bundle(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("alice", "aa", "bb", b"totp")
    keys.store_key_bundle(
        user,
        identity_pub=b"ik" * 16,
        signed_prekey_pub=b"spk" * 16,
        signed_prekey_sig=b"sig" * 32,
        pq_prekey_pub=b"pq" * 592,
        pq_prekey_sig=b"pqs" * 32,
    )
    bundle = keys.get_key_bundle(user)
    assert bundle is not None
    assert bundle.identity_pub == b"ik" * 16
    assert bundle.pq_prekey_pub == b"pq" * 592


def test_pop_one_time_prekey(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("bob", "aa", "bb", b"totp")
    keys.add_one_time_prekeys(user, [b"opk1" * 8, b"opk2" * 8])
    assert keys.pop_one_time_prekey(user) == b"opk1" * 8
    assert keys.pop_one_time_prekey(user) == b"opk2" * 8


def test_pop_returns_none_when_empty(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("carol", "aa", "bb", b"totp")
    assert keys.pop_one_time_prekey(user) is None


def test_count_one_time_prekeys(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("eve", "aa", "bb", b"totp")
    keys.add_one_time_prekeys(user, [b"k1" * 16, b"k2" * 16, b"k3" * 16])
    assert keys.count_one_time_prekeys(user) == 3


def test_get_key_bundle_returns_none_when_absent(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("frank", "aa", "bb", b"totp")
    assert keys.get_key_bundle(user) is None


def test_store_key_bundle_upserts_on_conflict(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("grace", "aa", "bb", b"totp")
    keys.store_key_bundle(
        user,
        identity_pub=b"ik1" * 16,
        signed_prekey_pub=b"spk" * 16,
        signed_prekey_sig=b"sig" * 32,
        pq_prekey_pub=b"pq" * 592,
        pq_prekey_sig=b"pqs" * 32,
    )
    keys.store_key_bundle(
        user,
        identity_pub=b"ik2" * 16,
        signed_prekey_pub=b"spk" * 16,
        signed_prekey_sig=b"sig" * 32,
        pq_prekey_pub=b"pq" * 592,
        pq_prekey_sig=b"pqs" * 32,
    )
    bundle = keys.get_key_bundle(user)
    assert bundle is not None
    assert bundle.identity_pub == b"ik2" * 16


def test_get_identity_pub_by_username(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("alice", "aa", "bb", b"totp")
    keys.store_key_bundle(
        user,
        identity_pub=b"ik" * 16,
        signed_prekey_pub=b"spk" * 16,
        signed_prekey_sig=b"sig" * 32,
        pq_prekey_pub=b"pq" * 592,
        pq_prekey_sig=b"pqs" * 32,
    )
    result = keys.get_identity_pub_by_username("alice")
    assert result is not None
    user_id, identity_pub = result
    assert user_id == user
    assert identity_pub == b"ik" * 16


def test_get_identity_pub_by_username_returns_none_when_no_bundle(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    users.create_user("alice", "aa", "bb", b"totp")
    assert keys.get_identity_pub_by_username("alice") is None


def test_get_identity_pub_by_username_returns_none_for_unknown_user(session):
    keys = SQLKeyBundleRepository(session)
    assert keys.get_identity_pub_by_username("nobody") is None


def test_count_returns_zero_when_no_prekeys(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("henry", "aa", "bb", b"totp")
    assert keys.count_one_time_prekeys(user) == 0
