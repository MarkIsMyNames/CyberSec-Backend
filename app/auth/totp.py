import os
import secrets

import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import config
from app.logger import logger


def _derive_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=config["crypto"]["encryption_key_length_bytes"],
        salt=None,
        info=config["crypto"]["hkdf_info_strings"]["encryption"].encode(),
    ).derive(bytes.fromhex(os.environ["SERVER_MASTER_SECRET"]))


def generate_totp_secret() -> str:
    secret = pyotp.random_base32()
    logger.debug("generated TOTP secret")
    return secret


def verify_totp(secret: str, code: str) -> bool:
    logger.debug("Attempt to verify TOPT")
    window = config["auth"]["totp_window"]
    result = pyotp.TOTP(secret).verify(code, valid_window=window)
    return result


def get_provisioning_uri(secret: str, username: str) -> str:
    logger.debug("generating TOTP provisioning URI username=%s", username)
    return pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=config["server"]["app_name"]
    )


def encrypt(plaintext: bytes) -> bytes:
    key = _derive_key()
    # Random nonce is safe here: each value is encrypted once per user,
    # so collision probability (~1 in 10^23 for 10^6 users) is negligible.
    nonce = secrets.token_bytes(config["crypto"]["nonce_length_bytes"])
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    logger.debug("encrypted nonce_len=%d ct_len=%d", len(nonce), len(ct))
    return nonce + ct


def decrypt(data: bytes) -> bytes:
    key = _derive_key()
    nonce_len = config["crypto"]["nonce_length_bytes"]
    nonce, ct = data[:nonce_len], data[nonce_len:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        logger.error("Decryption failed: authentication tag mismatch")
        raise
    logger.debug("Secret decrypted")
    return plaintext


