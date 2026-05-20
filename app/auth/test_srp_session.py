import time

import pytest
import srp

import app.auth.srp_session as srp_session_mod
from app.auth.srp_session import _SRP_HASH, _SRP_NG, _sessions, srp_init, srp_verify


@pytest.fixture(autouse=True)
def clear_sessions():
    _sessions.clear()
    yield
    _sessions.clear()


def _make_client(username: str, password: str):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=_SRP_HASH, ng_type=_SRP_NG
    )
    client = srp.User(username, password, hash_alg=_SRP_HASH, ng_type=_SRP_NG)
    return salt.hex(), verifier.hex(), client


def _do_init(username: str, salt_hex: str, verifier_hex: str, client):
    _, client_public_bytes = client.start_authentication()
    return srp_init(username, salt_hex, verifier_hex, client_public_bytes.hex())


class TestSrpInit:
    def test_returns_three_hex_strings(self):
        salt_hex, verifier_hex, client = _make_client("alice", "password")

        session_id, challenge_salt_hex, server_public_hex = _do_init(
            "alice", salt_hex, verifier_hex, client
        )

        assert isinstance(session_id, str) and len(session_id) == 64
        assert bytes.fromhex(challenge_salt_hex)
        assert bytes.fromhex(server_public_hex)

    def test_session_stored(self):
        salt_hex, verifier_hex, client = _make_client("bob", "password")

        session_id, _, _ = _do_init("bob", salt_hex, verifier_hex, client)

        assert session_id in _sessions
        assert _sessions[session_id].username == "bob"

    def test_session_ids_are_unique(self):
        salt_hex, verifier_hex, client1 = _make_client("alice", "password")
        salt_hex2, verifier_hex2, client2 = _make_client("alice", "password")

        sid1, _, _ = _do_init("alice", salt_hex, verifier_hex, client1)
        sid2, _, _ = _do_init("alice", salt_hex2, verifier_hex2, client2)

        assert sid1 != sid2


class TestSrpVerify:
    def test_valid_handshake_returns_username_and_proof(self):
        salt_hex, verifier_hex, client = _make_client("alice", "hunter2")
        session_id, challenge_salt_hex, server_public_hex = _do_init(
            "alice", salt_hex, verifier_hex, client
        )
        client_proof = client.process_challenge(
            bytes.fromhex(challenge_salt_hex), bytes.fromhex(server_public_hex)
        )

        returned_username, server_proof_hex = srp_verify(session_id, client_proof.hex())

        assert returned_username == "alice"
        assert isinstance(server_proof_hex, str)
        assert len(bytes.fromhex(server_proof_hex)) > 0

    def test_client_can_verify_server_proof(self):
        salt_hex, verifier_hex, client = _make_client("alice", "hunter2")
        session_id, challenge_salt_hex, server_public_hex = _do_init(
            "alice", salt_hex, verifier_hex, client
        )
        client_proof = client.process_challenge(
            bytes.fromhex(challenge_salt_hex), bytes.fromhex(server_public_hex)
        )
        _, server_proof_hex = srp_verify(session_id, client_proof.hex())

        client.verify_session(bytes.fromhex(server_proof_hex))

        assert client.authenticated()

    def test_session_consumed_after_verify(self):
        salt_hex, verifier_hex, client = _make_client("alice", "hunter2")
        session_id, challenge_salt_hex, server_public_hex = _do_init(
            "alice", salt_hex, verifier_hex, client
        )
        client_proof = client.process_challenge(
            bytes.fromhex(challenge_salt_hex), bytes.fromhex(server_public_hex)
        )
        srp_verify(session_id, client_proof.hex())

        assert session_id not in _sessions

    def test_unknown_session_raises(self):
        with pytest.raises(ValueError, match="not found or expired"):
            srp_verify("0" * 64, "deadbeef")

    def test_wrong_client_proof_raises(self):
        salt_hex, verifier_hex, client = _make_client("alice", "hunter2")
        session_id, _, _ = _do_init("alice", salt_hex, verifier_hex, client)

        with pytest.raises(ValueError, match="client proof invalid"):
            srp_verify(session_id, "deadbeef" * 8)

    def test_expired_session_raises(self):
        salt_hex, verifier_hex, client = _make_client("alice", "hunter2")
        session_id, challenge_salt_hex, server_public_hex = _do_init(
            "alice", salt_hex, verifier_hex, client
        )
        client_proof = client.process_challenge(
            bytes.fromhex(challenge_salt_hex), bytes.fromhex(server_public_hex)
        )
        _sessions[session_id].expires_at = time.monotonic() - 1

        with pytest.raises(ValueError, match="not found or expired"):
            srp_verify(session_id, client_proof.hex())


class TestPurgeExpired:
    def test_only_removes_expired(self):
        salt_hex1, verifier_hex1, client1 = _make_client("x", "password")
        expired_id, _, _ = _do_init("x", salt_hex1, verifier_hex1, client1)
        _sessions[expired_id].expires_at = time.monotonic() - 1

        salt_hex2, verifier_hex2, client2 = _make_client("y", "password")
        live_id, _, _ = _do_init("y", salt_hex2, verifier_hex2, client2)
        _sessions[live_id].expires_at = time.monotonic() + 9999

        srp_session_mod._purge_expired()

        assert expired_id not in _sessions
        assert live_id in _sessions
