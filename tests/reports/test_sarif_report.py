from __future__ import annotations

import json

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.reports.sarif_report import generate_sarif_report


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Return a list of sample findings for SARIF tests."""
    return [
        Finding(
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
        ),
        Finding(
            vx_id="VX-0002",
            scanner=ScannerMetadata(
                tool="gitleaks",
                scanner_type=ScannerType.SECRET,
                rule_id="aws-access-key",
            ),
            fingerprint="def456",
            message="AWS Access Key detected",
            severity=Severity.HIGH,
            location=Location(path="config/aws.yml", line_start=3),
            raw_finding={},
            evidence="AKIA****",
        ),
        Finding(
            vx_id="VX-0003",
            scanner=ScannerMetadata(
                tool="semgrep",
                scanner_type=ScannerType.SAST,
                rule_id="python.xss",
            ),
            fingerprint="ghi789",
            message="Reflected XSS",
            severity=Severity.MEDIUM,
            location=Location(path="src/views.py", line_start=25),
            raw_finding={},
        ),
    ]


def test_sarif_report_valid_structure(sample_findings: list[Finding]) -> None:
    """Assert SARIF document has required top-level structure."""
    output = generate_sarif_report(sample_findings, {})
    parsed = json.loads(output)
    assert parsed["version"] == "2.1.0"
    assert isinstance(parsed["runs"], list)
    assert len(parsed["runs"]) == 1
    assert "results" in parsed["runs"][0]
    assert "tool" in parsed["runs"][0]


def test_sarif_report_correct_result_count(sample_findings: list[Finding]) -> None:
    """Assert the number of results matches the number of findings."""
    output = generate_sarif_report(sample_findings, {})
    parsed = json.loads(output)
    assert len(parsed["runs"][0]["results"]) == len(sample_findings)


def test_sarif_report_severity_mapping() -> None:
    """Assert Verix severities map to correct SARIF levels."""
    findings = [
        Finding(
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
        ),
        Finding(
            vx_id="VX-0002",
            scanner=ScannerMetadata(
                tool="semgrep",
                scanner_type=ScannerType.SAST,
                rule_id="python.xss",
            ),
            fingerprint="def456",
            message="Reflected XSS",
            severity=Severity.MEDIUM,
            location=Location(path="src/views.py", line_start=25),
            raw_finding={},
        ),
        Finding(
            vx_id="VX-0003",
            scanner=ScannerMetadata(
                tool="semgrep",
                scanner_type=ScannerType.SAST,
                rule_id="python.info",
            ),
            fingerprint="ghi789",
            message="Info finding",
            severity=Severity.LOW,
            location=Location(path="src/info.py", line_start=1),
            raw_finding={},
        ),
    ]
    output = generate_sarif_report(findings, {})
    parsed = json.loads(output)
    results = parsed["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"
    assert results[2]["level"] == "note"


def test_sarif_report_fingerprint_present() -> None:
    """Assert finding fingerprint is present in SARIF fingerprints."""
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
    output = generate_sarif_report([finding], {})
    parsed = json.loads(output)
    result = parsed["runs"][0]["results"][0]
    assert result["fingerprints"]["verix/v1"] == "abc123"


def test_sarif_report_deduplicates_rules() -> None:
    """Assert rules list is deduplicated by rule_id."""
    findings = [
        Finding(
            vx_id="VX-0001",
            scanner=ScannerMetadata(
                tool="semgrep",
                scanner_type=ScannerType.SAST,
                rule_id="python.sql-injection",
            ),
            fingerprint="abc123",
            message="First SQL injection",
            severity=Severity.HIGH,
            location=Location(path="src/app.py", line_start=10),
            raw_finding={},
        ),
        Finding(
            vx_id="VX-0002",
            scanner=ScannerMetadata(
                tool="semgrep",
                scanner_type=ScannerType.SAST,
                rule_id="python.sql-injection",
            ),
            fingerprint="def456",
            message="Second SQL injection",
            severity=Severity.HIGH,
            location=Location(path="src/other.py", line_start=20),
            raw_finding={},
        ),
    ]
    output = generate_sarif_report(findings, {})
    parsed = json.loads(output)
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "python.sql-injection"


def test_sarif_report_empty_findings() -> None:
    """Assert empty findings produce valid SARIF with empty results."""
    output = generate_sarif_report([], {})
    parsed = json.loads(output)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"] == []
    assert parsed["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_report_semgrep_has_help_uri() -> None:
    """Assert semgrep findings include a helpUri in SARIF rules."""
    findings = [
        Finding(
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
        ),
    ]
    output = generate_sarif_report(findings, {})
    parsed = json.loads(output)
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert "helpUri" in rules[0]
    assert "semgrep.dev" in rules[0]["helpUri"]


def test_sarif_report_gitleaks_has_help_uri() -> None:
    """Assert gitleaks findings include the correct helpUri in SARIF rules."""
    findings = [
        Finding(
            vx_id="VX-0001",
            scanner=ScannerMetadata(
                tool="gitleaks",
                scanner_type=ScannerType.SECRET,
                rule_id="aws-access-key",
            ),
            fingerprint="def456",
            message="AWS Access Key detected",
            severity=Severity.HIGH,
            location=Location(path="config/aws.yml", line_start=3),
            raw_finding={},
            evidence="AKIA****",
        ),
    ]
    output = generate_sarif_report(findings, {})
    parsed = json.loads(output)
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["helpUri"] == "https://github.com/gitleaks/gitleaks"
