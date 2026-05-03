from __future__ import annotations

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.findings.normalize import normalize_findings, process_findings


def _make_finding(
    fingerprint: str,
    severity: Severity,
    rule_id: str = "python.sql-injection",
    path: str = "src/app.py",
    line: int | None = 10,
) -> Finding:
    """Create a Finding with the given fingerprint and severity."""
    return Finding(
        vx_id="VX-0000",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id=rule_id,
        ),
        fingerprint=fingerprint,
        message="Test finding",
        severity=severity,
        location=Location(path=path, line_start=line),
        raw_finding={},
    )


def test_normalize_assigns_sequential_ids():
    """normalize_findings assigns sequential VX-IDs starting from 1."""
    findings = [
        _make_finding("a", Severity.HIGH),
        _make_finding("b", Severity.MEDIUM),
    ]
    result = normalize_findings(findings)
    assert result[0].vx_id == "VX-0001"
    assert result[1].vx_id == "VX-0002"


def test_normalize_sorts_by_severity():
    """normalize_findings sorts findings by severity descending."""
    findings = [
        _make_finding("m", Severity.MEDIUM),
        _make_finding("c", Severity.CRITICAL),
        _make_finding("h", Severity.HIGH),
    ]
    result = normalize_findings(findings)
    assert [f.severity for f in result] == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]


def test_normalize_regenerates_fingerprints():
    """normalize_findings regenerates fingerprints from finding data."""
    finding = _make_finding("old", Severity.HIGH)
    result = normalize_findings([finding])
    assert result[0].fingerprint != "old"


def test_process_findings_dedupes_then_normalizes():
    """process_findings deduplicates then normalizes the remaining findings."""
    findings = [
        _make_finding("dup", Severity.HIGH),
        _make_finding("dup", Severity.MEDIUM),
    ]
    result = process_findings(findings)
    assert len(result) == 1
    assert result[0].vx_id == "VX-0001"
    assert result[0].severity == Severity.HIGH
