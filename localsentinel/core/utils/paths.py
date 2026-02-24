from __future__ import annotations

from pathlib import Path

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    "build",
    "dist",
}


def is_ignored(path: Path) -> bool:
    return any(part in IGNORE_DIRS for part in path.parts)

