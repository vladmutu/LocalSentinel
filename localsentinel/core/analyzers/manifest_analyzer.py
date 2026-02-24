from __future__ import annotations

from pathlib import Path

from localsentinel.core.utils.config import load_allowed_backends
from localsentinel.core.utils.findings import Finding
from localsentinel.core.utils.toml_loader import load_toml


def scan_build_backend(root: Path) -> list[dict]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return []

    data = load_toml(pyproject)
    build_system = data.get("build-system", {})
    backend = build_system.get("build-backend")
    if not backend:
        return []

    allowed = load_allowed_backends()
    if backend not in allowed:
        finding = Finding(
            vector="build_backend_hijack",
            severity="high",
            message=f"Non-standard build backend: {backend}",
            path=str(pyproject),
            details={"backend": backend},
        )
        return [finding.to_dict()]

    return []

