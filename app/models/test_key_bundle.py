from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.user import SQLUserRepository


def test_store_and_fetch_key_bundle(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("alice", "aa", "bb", b"totp")
    keys.store_key_bundle(
        user.id,
        identity_pub=b"ik" * 16,
        signed_prekey_pub=b"spk" * 16,
        signed_prekey_sig=b"sig" * 32,
        pq_prekey_pub=b"pq" * 592,
        pq_prekey_sig=b"pqs" * 32,
    )
    bundle = keys.get_key_bundle(user.id)
    assert bundle is not None
    assert bundle.identity_pub == b"ik" * 16
    assert bundle.pq_prekey_pub == b"pq" * 592


def test_pop_one_time_prekey(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("bob", "aa", "bb", b"totp")
    keys.add_one_time_prekeys(user.id, [b"opk1" * 8, b"opk2" * 8])
    assert keys.pop_one_time_prekey(user.id) == b"opk1" * 8
    assert keys.pop_one_time_prekey(user.id) == b"opk2" * 8


def test_pop_returns_none_when_empty(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("carol", "aa", "bb", b"totp")
    assert keys.pop_one_time_prekey(user.id) is None


def test_count_one_time_prekeys(session):
    users = SQLUserRepository(session)
    keys = SQLKeyBundleRepository(session)
    user = users.create_user("eve", "aa", "bb", b"totp")
    keys.add_one_time_prekeys(user.id, [b"k1" * 16, b"k2" * 16, b"k3" * 16])
    assert keys.count_one_time_prekeys(user.id) == 3
