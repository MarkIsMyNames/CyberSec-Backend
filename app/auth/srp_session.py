from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

import srp

from app.config import config
from app.logger import logger

_SRP_NG = srp.NG_4096
_SRP_HASH = srp.SHA256


@dataclass
class SRPSession:
    username: str
    verifier: srp.Verifier
    expires_at: float


_sessions: dict[str, SRPSession] = {}


def srp_init(
    username: str, srp_salt_hex: str, srp_verifier_hex: str, client_public_hex: str
) -> tuple[str, str, str]:
    _purge_expired()
    salt = bytes.fromhex(srp_salt_hex)
    verifier = bytes.fromhex(srp_verifier_hex)
    client_public = bytes.fromhex(client_public_hex)

    # bind client's public key to the verifier and generate the server's challenge
    verifier_srp = srp.Verifier(
        username, salt, verifier, client_public, hash_alg=_SRP_HASH, ng_type=_SRP_NG
    )
    challenge_salt, server_public = verifier_srp.get_challenge()

    session_id = secrets.token_hex(config["auth"]["secret_token_bytes"])
    ttl = config["auth"]["srp_session_ttl_seconds"]
    _sessions[session_id] = SRPSession(
        username=username, verifier=verifier_srp, expires_at=time.monotonic() + ttl
    )
    logger.debug("srp session created username=%s", username)
    return session_id, challenge_salt.hex(), server_public.hex()


def srp_verify(session_id: str, client_proof_hex: str) -> tuple[str, str]:
    _purge_expired()
    entry = _sessions.pop(session_id, None)
    if entry is None:
        logger.warning("srp verify failed: session not found")
        raise ValueError("SRP session not found or expired")
    if time.monotonic() > entry.expires_at:
        logger.warning(
            "srp verify failed: session expired username=%s",
            entry.username,
        )
        raise ValueError("SRP session not found or expired")

    server_proof = entry.verifier.verify_session(bytes.fromhex(client_proof_hex))
    if server_proof is None or not entry.verifier.authenticated():
        logger.warning(
            "srp verify failed: invalid client proof username=%s",
            entry.username,
        )
        raise ValueError("SRP client proof invalid")

    logger.debug(
        "srp session verified username=%s", entry.username
    )
    return entry.username, server_proof.hex()


def _purge_expired() -> None:
    now = time.monotonic()
    # snapshot keys first to avoid mutating the dict while iterating
    expired = [
        session_id
        for session_id, session in _sessions.items()
        if now > session.expires_at
    ]
    for session_id in expired:
        del _sessions[session_id]
    if expired:
        logger.debug("purged %d expired srp sessions", len(expired))
