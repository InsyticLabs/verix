from __future__ import annotations

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.reports.markdown_report import generate_markdown_report


def test_markdown_report_contains_header() -> None:
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
    output = generate_markdown_report([finding], {"root_dir": "/tmp", "scanners": ["semgrep"]})
    assert "# Verix Security Report" in output


def test_markdown_report_contains_finding_id() -> None:
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
    output = generate_markdown_report([finding], {"root_dir": "/tmp", "scanners": ["semgrep"]})
    assert "VX-0001" in output


def test_markdown_report_contains_severity() -> None:
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
    output = generate_markdown_report([finding], {"root_dir": "/tmp", "scanners": ["semgrep"]})
    assert "HIGH" in output


def test_markdown_report_empty_findings() -> None:
    output = generate_markdown_report([], {"root_dir": "/tmp", "scanners": []})
    assert "No findings. Your code looks clean." in output
