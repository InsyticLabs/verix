from __future__ import annotations

from verix.findings.dedupe import deduplicate
from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity


def _make_finding(
    fingerprint: str,
    severity: Severity,
    metadata: dict[str, str] | None = None,
    rule_id: str = "python.sql-injection",
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
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
        metadata=metadata,
    )


def test_dedupe_removes_duplicate_fingerprints():
    """deduplicate returns only one finding per fingerprint."""
    findings = [
        _make_finding("abc123", Severity.HIGH),
        _make_finding("abc123", Severity.HIGH),
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_dedupe_keeps_higher_severity():
    """deduplicate keeps the finding with the highest severity."""
    findings = [
        _make_finding("dup", Severity.MEDIUM),
        _make_finding("dup", Severity.HIGH),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


def test_dedupe_keeps_finding_with_metadata_when_severity_equal():
    """deduplicate prefers the finding with metadata when severity is equal."""
    findings = [
        _make_finding("dup", Severity.HIGH, metadata=None),
        _make_finding("dup", Severity.HIGH, metadata={"cwe": "CWE-89"}),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].metadata == {"cwe": "CWE-89"}


def test_dedupe_preserves_order():
    """deduplicate preserves the relative order of kept findings."""
    findings = [
        _make_finding("a", Severity.HIGH),
        _make_finding("b", Severity.MEDIUM),
        _make_finding("c", Severity.LOW),
    ]
    result = deduplicate(findings)
    assert [f.fingerprint for f in result] == ["a", "b", "c"]
