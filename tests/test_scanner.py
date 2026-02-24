from pathlib import Path

from localsentinel.core.scanner import scan_package


def test_empty_package(tmp_path: Path) -> None:
    result = scan_package(tmp_path)
    assert result["risk_score"] == 0
    assert result["label"] == "none"
