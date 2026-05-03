from __future__ import annotations

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample Finding for use in tests."""
    return Finding(
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
