import pyotp
import srp

from app.auth.totp import decrypt
from app.repositories.user import SQLUserRepository


def srp_register(client, username: str, password: str):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex() if isinstance(salt, bytes) else salt,
            "srp_verifier": verifier.hex() if isinstance(verifier, bytes) else verifier,
        },
    )


def srp_login(client, username: str, password: str) -> dict:
    usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    username_out, client_public = usr.start_authentication()

    init = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": username_out,
            "client_public": client_public.hex(),
        },
    ).json()

    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    return client.post(
        "/api/v1/auth/srp-verify",
        json={
            "session_id": init["session_id"],
            "client_proof": client_proof.hex(),
        },
    ).json()


def auth_helper(client, session, username: str, password: str = "correcthorsebattery"):
    salt, verifier = srp.create_salted_verification_key(
        username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096
    )
    client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
        },
    )

    usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_4096)
    username_out, client_public = usr.start_authentication()
    init = client.post(
        "/api/v1/auth/srp-init",
        json={
            "username": username_out,
            "client_public": client_public.hex(),
        },
    ).json()
    client_proof = usr.process_challenge(
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["server_public"])
    )
    srp_resp = client.post(
        "/api/v1/auth/srp-verify",
        json={
            "session_id": init["session_id"],
            "client_proof": client_proof.hex(),
        },
    ).json()

    repo = SQLUserRepository(session)
    user = repo.get_user_by_username(username)
    assert user is not None
    totp_secret = decrypt(bytes(user.totp_secret_enc)).decode()
    code = pyotp.TOTP(totp_secret).now()
    tokens = client.post(
        "/api/v1/auth/verify-2fa",
        json={
            "totp_code": code,
            "pre_auth_token": srp_resp["pre_auth_token"],
        },
    ).json()
    return user, tokens["access_token"], tokens
