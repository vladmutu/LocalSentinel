from __future__ import annotations

import json
from pathlib import Path


def _config_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "config"


def load_sensitive_binaries() -> set[str]:
    path = _config_dir() / "sensitive_binaries.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item) for item in data}


def load_allowed_backends() -> set[str]:
    path = _config_dir() / "allowed_backends.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item) for item in data}

