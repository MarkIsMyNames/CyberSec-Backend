import json
from pathlib import Path
from typing import Any

config: dict[str, Any] = {}


def get_config() -> dict[str, Any]:
    global config
    if not config:
        with open(Path(__file__).parent / "config.json") as file:
            config = json.load(file)
    return config
