from __future__ import annotations

import os
import secrets

import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import config
from app.logger import logger


def _totp_enc_key() -> bytes:
    secret = bytes.fromhex(os.environ["SERVER_MASTER_SECRET"])
    info = config["crypto"]["hkdf_info_strings"]["totp_encryption"].encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=config["crypto"]["totp_key_length_bytes"], salt=None, info=info)
    return hkdf.derive(secret)


def generate_totp_secret() -> str:
    secret = pyotp.random_base32()
    logger.debug("generated TOTP secret")
    return secret


def verify_totp(secret: str, code: str) -> bool:
    window = config["auth"]["totp_window"]
    result = pyotp.TOTP(secret).verify(code, valid_window=window)
    if not result:
        logger.warning("TOTP verification failed")
    return result


def get_provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=config["server"]["app_name"])


def encrypt_totp_secret(secret: str) -> bytes:
    key = _totp_enc_key()
    nonce_len = config["crypto"]["nonce_length_bytes"]
    nonce = secrets.token_bytes(nonce_len)
    ct = AESGCM(key).encrypt(nonce, secret.encode(), None)
    logger.debug("TOTP secret encrypted")
    return nonce + ct


def decrypt_totp_secret(data: bytes) -> str:
    key = _totp_enc_key()
    nonce_len = config["crypto"]["nonce_length_bytes"]
    nonce, ct = data[:nonce_len], data[nonce_len:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()
