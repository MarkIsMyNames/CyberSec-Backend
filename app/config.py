import json
from pathlib import Path
from typing import Any

_config_path = Path(__file__).parent / "config.json"
if not _config_path.exists():
    raise FileNotFoundError("config.json not found at %s" % _config_path)

config: dict[str, Any] = json.loads(_config_path.read_text())
