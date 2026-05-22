import os
from pathlib import Path
from threading import Lock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import NullPool
import sqlcipher3.dbapi2 as sqlcipher
from sqlcipher3.dbapi2 import Connection

from app.config import config
from app.logger import logger

engine: Engine | None = None
engine_lock: Lock = Lock()


def _derive_db_key() -> str:
    cfg = config["crypto"]
    secret = bytes.fromhex(os.environ["SERVER_MASTER_SECRET"])
    info = cfg["hkdf_info_strings"]["database_key"].encode()
    length = cfg["database_key_length_bytes"]
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    logger.debug("derived database key via HKDF-SHA256 length=%d", length)
    return hkdf.derive(secret).hex()


def _make_engine() -> Engine:
    cfg = config["server"]
    db_path = Path(__file__).parent.parent / cfg["db_path"]
    key = _derive_db_key()
    logger.debug("creating SQLCipher engine path=%s", db_path)

    def creator() -> Connection:
        conn = sqlcipher.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA key = \"x'%s'\"" % key)    # must be first — unlocks the encrypted database
        conn.execute("PRAGMA foreign_keys = ON")        # enforce FK constraints (SQLite disables them by default)
        conn.execute("PRAGMA journal_mode = WAL")       # readers don't block writers; writers don't block readers
        conn.execute("PRAGMA busy_timeout = 5000")      # retry writes for up to 5s before raising SQLITE_BUSY
        conn.execute("PRAGMA synchronous = NORMAL")     # fsync on WAL checkpoints only — safe with WAL, faster than FULL
        conn.execute("PRAGMA cache_size = -64000")      # 64 MB page cache per connection (negative = kibibytes)
        return conn

    return create_engine(cfg["db_url"], creator=creator, poolclass=NullPool)


def get_engine() -> Engine:
    global engine
    if engine is None:
        candidate = _make_engine()
        with engine_lock:
            if engine is None:
                engine = candidate
            else:
                candidate.dispose()
    if engine is None:
        raise RuntimeError("engine initialisation failed")
    return engine
