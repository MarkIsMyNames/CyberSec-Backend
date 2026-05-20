from app.models.base import Base
from app.session import _make_engine
from app.logger import logger


def init_db() -> None:
    logger.info("initialising database schema")
    Base.metadata.create_all(_make_engine())
    logger.info("database schema ready — %d tables", len(Base.metadata.tables))
