import os
from threading import Lock

from sqlalchemy import Engine, create_engine

from app.config import config
from app.logger import logger

engine: Engine | None = None
engine_lock: Lock = Lock()


def _make_engine() -> Engine:
    url = os.environ["DATABASE_URL"]
    logger.debug("creating PostgreSQL engine")
    return create_engine(
        url,
        pool_size=config["server"]["db_pool_size"],
        max_overflow=config["server"]["db_max_overflow"],
        pool_pre_ping=True,
    )


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


def reset_engine() -> None:
    global engine
    with engine_lock:
        if engine is not None:
            engine.dispose()
        engine = None
