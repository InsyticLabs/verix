from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.mcp.server import (
    explain_finding,
    fix_context,
    generate_report,
    verify_finding,
)


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
        metadata={"cwe": ["CWE-89"], "owasp": ["A03:2021 - Injection"]},
    )


def test_explain_finding_returns_details(sample_finding: Finding) -> None:
    """Assert explain_finding returns detailed info for a matching finding."""
    with patch(
        "verix.mcp.server.load_scan_cache",
        return_value=[sample_finding],
    ):
        result = explain_finding(finding_id="VX-0001")

    data = json.loads(result)
    assert data["finding_id"] == "VX-0001"
    assert "severity" in data
    assert data["severity"] == "high"
    assert data["file"] == "src/app.py"
    assert data["scanner"] == "semgrep"
    assert data["cwe"] == ["CWE-89"]


def test_explain_finding_returns_error_when_not_found(sample_finding: Finding) -> None:
    """Assert explain_finding returns an error when finding is not found."""
    with patch(
        "verix.mcp.server.load_scan_cache",
        return_value=[sample_finding],
    ):
        result = explain_finding(finding_id="VX-9999")

    data = json.loads(result)
    assert "error" in data


def test_fix_context_returns_prompt(sample_finding: Finding) -> None:
    """Assert fix_context returns a JSON prompt for a finding."""
    mock_ctx = MagicMock()
    mock_ctx.language = "python"
    mock_ctx.file_path = "src/app.py"

    with (
        patch(
            "verix.mcp.server.load_scan_cache",
            return_value=[sample_finding],
        ),
        patch(
            "verix.mcp.server.extract_fix_context",
            return_value=mock_ctx,
        ),
        patch(
            "verix.mcp.server.format_fix_prompt",
            return_value="fix prompt string",
        ),
    ):
        result = fix_context(finding_id="VX-0001")

    data = json.loads(result)
    assert data["prompt"] == "fix prompt string"
    assert data["finding_id"] == "VX-0001"
    assert data["language"] == "python"


def test_verify_finding_returns_outcome(sample_finding: Finding) -> None:
    """Assert verify_finding returns the verification outcome."""
    mock_result = MagicMock()
    mock_result.outcome.value = "fixed"
    mock_result.message = "Finding no longer detected."
    mock_result.remaining_findings = []

    with (
        patch(
            "verix.mcp.server.load_scan_cache",
            return_value=[sample_finding],
        ),
        patch(
            "verix.mcp.server._verify_finding",
            return_value=mock_result,
        ),
    ):
        result = verify_finding(finding_id="VX-0001")

    data = json.loads(result)
    assert data["outcome"] == "fixed"
    assert data["message"] == "Finding no longer detected."
    assert data["remaining_count"] == 0


def test_generate_report_returns_markdown(sample_finding: Finding) -> None:
    """Assert generate_report returns markdown containing Verix."""
    with (
        patch(
            "verix.mcp.server.load_scan_cache",
            return_value=[sample_finding],
        ),
        patch(
            "verix.mcp.server.generate_markdown_report",
            return_value="# Verix Report\n\nmarkdown content",
        ),
    ):
        result = generate_report(format="markdown")

    assert "Verix" in result


def test_generate_report_returns_error_on_invalid_format(sample_finding: Finding) -> None:
    """Assert generate_report returns an error for an unsupported format."""
    with patch(
        "verix.mcp.server.load_scan_cache",
        return_value=[sample_finding],
    ):
        result = generate_report(format="xml")

    data = json.loads(result)
    assert "error" in data
