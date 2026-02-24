from __future__ import annotations

import ast
from math import log2
from pathlib import Path

from localsentinel.core.utils.findings import Finding
from localsentinel.core.utils.paths import is_ignored

SINK_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
    "execfile",
}

SINK_MODULE_FUNCTIONS = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("os", "system"),
}


def scan_entropy(root: Path, threshold: float = 6.0) -> list[dict]:
    findings: list[dict] = []
    for path in root.rglob("*.py"):
        if is_ignored(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if is_sink_call(node):
                for literal in extract_string_literals(node):
                    entropy_value = entropy(literal)
                    if entropy_value > threshold:
                        finding = Finding(
                            vector="ast_entropy",
                            severity="high",
                            message="High entropy string in sink call context",
                            path=str(path),
                            details={
                                "entropy": round(entropy_value, 2),
                                "snippet": literal[:80],
                            },
                        )
                        findings.append(finding.to_dict())
    return findings


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def is_sink_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in SINK_FUNCTIONS
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (func.value.id, func.attr) in SINK_MODULE_FUNCTIONS
    return False


def extract_string_literals(node: ast.Call) -> list[str]:
    literals: list[str] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            literals.append(arg.value)
    for keyword in node.keywords:
        if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            literals.append(keyword.value.value)
    return literals

