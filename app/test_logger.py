import logging.handlers


def test_logger_has_rotating_file_handler():
    from app.logger import logger

    assert any(
        isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers
    )
