import logging
import logging.handlers


def test_logger_has_rotating_file_handler():
    from app.logger import logger

    assert any(
        isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers
    )


def test_logger_emits_record():
    from app.logger import logger

    records = []
    stream = logging.StreamHandler()
    stream.emit = lambda r: records.append(r)
    logger.addHandler(stream)
    try:
        logger.info("test message")
        assert any("test message" in r.getMessage() for r in records)
    finally:
        logger.removeHandler(stream)
