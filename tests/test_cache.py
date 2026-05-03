from __future__ import annotations

from pathlib import Path

import pytest

from verix.cache import load_scan_cache, save_scan_cache
from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity


def test_cache_roundtrip(tmp_path: Path) -> None:
    finding = Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="python.sql-injection",
        ),
        fingerprint="abc123",
        message="Possible SQL injection",
        severity=Severity.HIGH,
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
    )
    cache_dir = str(tmp_path / "cache")
    file_path = save_scan_cache([finding], cache_dir=cache_dir)
    assert file_path.endswith("last_scan.json")

    loaded = load_scan_cache(cache_dir=cache_dir)
    assert len(loaded) == 1
    assert loaded[0].vx_id == finding.vx_id
    assert loaded[0].severity == finding.severity
    assert loaded[0].message == finding.message


def test_cache_load_raises_when_missing(tmp_path: Path) -> None:
    cache_dir = str(tmp_path / "nonexistent")
    with pytest.raises(FileNotFoundError, match="No scan cache found"):
        load_scan_cache(cache_dir=cache_dir)
