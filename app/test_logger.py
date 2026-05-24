import logging.handlers

from app.logger import logger


def test_logger_has_rotating_file_handler():
    assert any(
        isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers
    )
