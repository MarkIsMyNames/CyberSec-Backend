from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
import sqlcipher3.dbapi2 as sqlcipher

from app.config import get_config
from app.logger import logger


def _derive_db_key() -> str:
    cfg = get_config()["crypto"]
    secret = bytes.fromhex(os.environ["SERVER_MASTER_SECRET"])
    info = cfg["hkdf_info_strings"]["database_key"].encode()
    length = cfg["database_key_length_bytes"]
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    logger.debug("derived database key via HKDF-SHA256 length=%d", length)
    return hkdf.derive(secret).hex()


def _make_engine():
    cfg = get_config()["server"]
    db_path = Path(__file__).parent.parent / cfg["db_path"]
    key = _derive_db_key()
    logger.debug("creating SQLCipher engine path=%s", db_path)

    def creator():
        conn = sqlcipher.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA key = \"x'%s'\"" % key)  # unlock SQLCipher AES-256-CBC encryption; must be first query
        conn.execute("PRAGMA foreign_keys = ON")  # SQLite disables FK enforcement by default; must re-enable per connection
        return conn

    return create_engine(cfg["db_url"], creator=creator, poolclass=NullPool)
