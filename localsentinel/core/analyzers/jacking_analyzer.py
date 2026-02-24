from __future__ import annotations

import ast
from pathlib import Path

from localsentinel.core.utils.config import load_sensitive_binaries
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


def scan_command_jacking(root: Path) -> list[dict]:
    findings: list[dict] = []
    scripts = extract_console_scripts(root)
    sensitive = load_sensitive_binaries()
    for name, entry in scripts.items():
        if name not in sensitive:
            continue

        module_name, _, _ = entry.partition(":")
        module_path = find_module_file(root, module_name.strip()) if module_name else None
        if not module_path:
            finding = Finding(
                vector="command_jacking",
                severity="medium",
                message=f"Console script '{name}' collides with sensitive binary",
                path=None,
                details={"entrypoint": entry},
            )
            findings.append(finding.to_dict())
            continue

        behavior = analyze_wrapper(module_path, name)
        severity = "low"
        if behavior.get("uses_sys_argv") and behavior.get("uses_subprocess") and behavior.get("calls_target"):
            severity = "high"
        elif behavior.get("uses_sys_argv") and behavior.get("uses_subprocess"):
            severity = "medium"

        finding = Finding(
            vector="command_jacking",
            severity=severity,
            message=f"Console script '{name}' collides with sensitive binary",
            path=str(module_path),
            details={"entrypoint": entry, **behavior},
        )
        findings.append(finding.to_dict())

    return findings


def extract_console_scripts(root: Path) -> dict[str, str]:
    scripts: dict[str, str] = {}

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = load_pyproject_scripts(pyproject)
        scripts.update(data)

    for path in root.rglob("entry_points.txt"):
        if is_ignored(path):
            continue
        for name, value in parse_entry_points_file(path).items():
            scripts.setdefault(name, value)

    return scripts


def load_pyproject_scripts(pyproject: Path) -> dict[str, str]:
    from localsentinel.core.utils.toml_loader import load_toml

    scripts: dict[str, str] = {}
    data = load_toml(pyproject)
    project = data.get("project", {})
    project_scripts = project.get("scripts", {})
    if isinstance(project_scripts, dict):
        for name, value in project_scripts.items():
            scripts[str(name)] = str(value)

    entry_points = project.get("entry-points", {})
    if isinstance(entry_points, dict):
        console_scripts = entry_points.get("console_scripts", {})
        if isinstance(console_scripts, dict):
            for name, value in console_scripts.items():
                scripts[str(name)] = str(value)

    return scripts


def parse_entry_points_file(path: Path) -> dict[str, str]:
    scripts: dict[str, str] = {}
    section = None
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return scripts

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != "console_scripts":
            continue
        if "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        scripts[name.strip()] = value.strip()
    return scripts


def find_module_file(root: Path, module_name: str) -> Path | None:
    module_path = Path(*module_name.split("."))
    candidates = [
        root / (str(module_path) + ".py"),
        root / module_path / "__init__.py",
        root / "src" / (str(module_path) + ".py"),
        root / "src" / module_path / "__init__.py",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def analyze_wrapper(path: Path, target_binary: str) -> dict:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return {}

    uses_sys_argv = False
    uses_subprocess = False
    uses_network = False
    calls_target = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "sys" and node.attr == "argv":
                uses_sys_argv = True

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in SINK_FUNCTIONS:
                pass
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if (func.value.id, func.attr) in SINK_MODULE_FUNCTIONS:
                    uses_subprocess = True
                    if call_uses_target(node, target_binary):
                        calls_target = True
            if isinstance(func, ast.Name) and func.id in {"system"}:
                uses_subprocess = True

        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"requests", "socket", "urllib", "urllib3"}:
                    uses_network = True
        if isinstance(node, ast.ImportFrom):
            if node.module in {"requests", "socket", "urllib", "urllib.request", "urllib3"}:
                uses_network = True

    return {
        "uses_sys_argv": uses_sys_argv,
        "uses_subprocess": uses_subprocess,
        "uses_network": uses_network,
        "calls_target": calls_target,
    }


def call_uses_target(call: ast.Call, target_binary: str) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value == target_binary:
                return True
        if isinstance(arg, (ast.List, ast.Tuple)):
            for element in arg.elts:
                if isinstance(element, ast.Constant) and isinstance(element.value, str):
                    if element.value == target_binary:
                        return True
    return False

