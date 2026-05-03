from __future__ import annotations

import pytest

from verix.findings.fingerprint import generate_fingerprint
from verix.findings.models import (
    Finding,
    Location,
    ScannerMetadata,
    ScannerType,
    Severity,
)
from verix.fix.verify import VerifyOutcome, verify_finding


def _make_finding(
    path: str = "/tmp/test.py",
    scanner_type: ScannerType = ScannerType.SAST,
    fingerprint: str | None = None,
    rule_id: str = "test-rule",
) -> Finding:
    """Create a minimal Finding for testing."""
    tool = "semgrep" if scanner_type == ScannerType.SAST else "gitleaks"
    fp = fingerprint or generate_fingerprint(tool, rule_id, path, 1)
    return Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool=tool,
            scanner_type=scanner_type,
            rule_id=rule_id,
        ),
        fingerprint=fp,
        message="Test finding",
        severity=Severity.HIGH,
        location=Location(
            path=path,
            line_start=1,
            line_end=1,
        ),
        raw_finding={},
    )


def test_verify_returns_inconclusive_for_unknown_scanner_type() -> None:
    """verify_finding returns INCONCLUSIVE for unsupported scanner types."""
    finding = _make_finding(scanner_type=ScannerType.POLICY)
    result = verify_finding(finding)
    assert result.outcome == VerifyOutcome.INCONCLUSIVE
    assert "No scanner available" in result.message


def test_verify_returns_inconclusive_when_scanner_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """verify_finding returns INCONCLUSIVE when the scanner binary is missing."""
    finding = _make_finding()
    monkeypatch.setattr("verix.scanners.semgrep.SemgrepScanner.is_available", lambda self: False)
    result = verify_finding(finding)
    assert result.outcome == VerifyOutcome.INCONCLUSIVE
    assert "not available" in result.message


def test_verify_returns_fixed_when_fingerprint_not_in_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """verify_finding returns FIXED when re-scan yields no matching findings."""
    finding = _make_finding()
    monkeypatch.setattr("verix.scanners.semgrep.SemgrepScanner.is_available", lambda self: True)
    monkeypatch.setattr("verix.scanners.semgrep.SemgrepScanner.scan", lambda self, request: [])
    result = verify_finding(finding)
    assert result.outcome == VerifyOutcome.FIXED
    assert result.remaining_findings == []


def test_verify_returns_still_present_when_fingerprint_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """verify_finding returns STILL_PRESENT when re-scan finds the same fingerprint."""
    finding = _make_finding()
    raw_result = Finding(
        vx_id="VX-0000",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="test-rule",
        ),
        fingerprint=generate_fingerprint("semgrep", "test-rule", "/tmp/test.py", 1),
        message="Test finding",
        severity=Severity.HIGH,
        location=Location(
            path="/tmp/test.py",
            line_start=1,
            line_end=1,
        ),
        raw_finding={},
    )
    monkeypatch.setattr("verix.scanners.semgrep.SemgrepScanner.is_available", lambda self: True)
    monkeypatch.setattr(
        "verix.scanners.semgrep.SemgrepScanner.scan",
        lambda self, request: [raw_result],
    )
    result = verify_finding(finding)
    assert result.outcome == VerifyOutcome.STILL_PRESENT
    assert len(result.remaining_findings) == 1
