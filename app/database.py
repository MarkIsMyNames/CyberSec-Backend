from app.models.base import Base
from app.session import get_engine
from app.logger import logger


def init_db() -> None:
    logger.info("initialising database schema")
    Base.metadata.create_all(get_engine())
    logger.info("database schema ready — %d tables", len(Base.metadata.tables))
