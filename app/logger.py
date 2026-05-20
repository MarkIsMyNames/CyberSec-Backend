import logging.handlers
from pathlib import Path
from app.config import get_config

config_logger = get_config()["logging"]

handler = logging.handlers.RotatingFileHandler(
    Path(__file__).parent.parent / config_logger["log_file"],
    maxBytes=config_logger["log_max_bytes"],
    backupCount=config_logger["log_backup_count"],
)
handler.setFormatter(logging.Formatter(config_logger["log_format"]))

logger = logging.getLogger(config_logger["logger_name"])
logger.setLevel(config_logger["log_level"])
logger.addHandler(handler)
