from __future__ import annotations

from pathlib import Path

from localsentinel.core.analyzers.entropy_analyzer import scan_entropy
from localsentinel.core.analyzers.jacking_analyzer import scan_command_jacking
from localsentinel.core.analyzers.manifest_analyzer import scan_build_backend
from localsentinel.core.analyzers.persistence_analyzer import scan_pth_persistence
from localsentinel.models.heuristics import score_findings


def scan_package(path: Path) -> dict:
    findings: list[dict] = []
    findings.extend(scan_build_backend(path))
    findings.extend(scan_pth_persistence(path))
    findings.extend(scan_command_jacking(path))
    findings.extend(scan_entropy(path))

    score = score_findings(findings)
    return {
        "risk_score": score["risk_score"],
        "label": score["label"],
        "severity_counts": score["severity_counts"],
        "vector_counts": score["vector_counts"],
        "details": findings,
    }

