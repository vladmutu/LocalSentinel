from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    vector: str
    severity: str
    message: str
    path: str | None = None
    details: dict | None = None

    def to_dict(self) -> dict:
        return {
            "vector": self.vector,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "details": self.details or {},
        }

