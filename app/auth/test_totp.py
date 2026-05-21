import base64

import pyotp

from app.auth.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp,
)


def test_generate_secret_is_base32():
    secret = generate_totp_secret()
    assert len(secret) > 0
    base64.b32decode(secret)  # raises if invalid


def test_verify_totp_correct_code(test_env):
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp(secret, code) is True


def test_verify_totp_wrong_code(test_env):
    secret = generate_totp_secret()
    assert verify_totp(secret, "000000") is False


def test_provisioning_uri_contains_username():
    secret = generate_totp_secret()
    uri = get_provisioning_uri(secret, username="alice")
    assert "alice" in uri
    assert uri.startswith("otpauth://totp/")


def test_encrypt_decrypt_totp_secret(test_env):
    secret = "BASE32SECRET"
    enc = encrypt_totp_secret(secret)
    assert isinstance(enc, bytes)
    assert decrypt_totp_secret(enc) == secret
