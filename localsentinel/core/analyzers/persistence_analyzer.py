from __future__ import annotations

from pathlib import Path

from localsentinel.core.utils.findings import Finding
from localsentinel.core.utils.paths import is_ignored


def scan_pth_persistence(root: Path) -> list[dict]:
    findings: list[dict] = []
    for path in root.rglob("*.pth"):
        if is_ignored(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("import ") or stripped == "import" or stripped.startswith("import\t"):
                finding = Finding(
                    vector="pth_persistence",
                    severity="critical",
                    message=".pth file executes import at interpreter startup",
                    path=str(path),
                    details={"line": stripped[:120]},
                )
                findings.append(finding.to_dict())
                break
    return findings

