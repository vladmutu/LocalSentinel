from __future__ import annotations

from collections import Counter

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 20,
}


def score_findings(findings: list[dict]) -> dict:
    if not findings:
        return {
            "risk_score": 0,
            "severity_counts": {},
            "vector_counts": {},
            "label": "none",
        }

    severity_counts = Counter(item.get("severity", "unknown") for item in findings)
    vector_counts = Counter(item.get("vector", "unknown") for item in findings)

    max_severity_weight = max(
        (SEVERITY_WEIGHTS.get(severity, 0) for severity in severity_counts.keys()),
        default=0,
    )
    bonus = min(30, 5 * len(findings))
    risk_score = min(100, max_severity_weight + bonus)

    label = "low"
    if risk_score >= 90:
        label = "critical"
    elif risk_score >= 70:
        label = "high"
    elif risk_score >= 40:
        label = "medium"

    return {
        "risk_score": risk_score,
        "severity_counts": dict(severity_counts),
        "vector_counts": dict(vector_counts),
        "label": label,
    }

