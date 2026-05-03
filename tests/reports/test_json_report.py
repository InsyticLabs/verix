from __future__ import annotations

import json

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.reports.json_report import generate_json_report


@pytest.fixture
def sample_findings() -> list[Finding]:
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


def test_json_report_returns_valid_json(sample_findings: list[Finding]) -> None:
    meta = {"root_dir": "/tmp/project", "scanners": ["semgrep", "gitleaks"]}
    output = generate_json_report(sample_findings, meta)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_json_report_has_required_keys(sample_findings: list[Finding]) -> None:
    meta = {"root_dir": "/tmp/project", "scanners": ["semgrep", "gitleaks"]}
    output = generate_json_report(sample_findings, meta)
    parsed = json.loads(output)
    assert "verix_version" in parsed
    assert "scan_time" in parsed
    assert "total" in parsed
    assert "by_severity" in parsed
    assert "findings" in parsed
    assert "meta" in parsed


def test_json_report_severity_counts_are_correct(sample_findings: list[Finding]) -> None:
    meta = {"root_dir": "/tmp/project", "scanners": ["semgrep", "gitleaks"]}
    output = generate_json_report(sample_findings, meta)
    parsed = json.loads(output)
    assert parsed["by_severity"]["high"] == 2
    assert parsed["by_severity"]["medium"] == 1
    assert parsed["by_severity"]["critical"] == 0
    assert parsed["by_severity"]["low"] == 0
    assert parsed["by_severity"]["info"] == 0


def test_json_report_finding_count_matches(sample_findings: list[Finding]) -> None:
    meta = {"root_dir": "/tmp/project", "scanners": ["semgrep", "gitleaks"]}
    output = generate_json_report(sample_findings, meta)
    parsed = json.loads(output)
    assert len(parsed["findings"]) == len(sample_findings)
    assert parsed["total"] == len(sample_findings)
