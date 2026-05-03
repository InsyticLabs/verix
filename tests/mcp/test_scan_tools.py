from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.mcp.server import get_findings, scan_diff, scan_file, scan_repo


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


def test_scan_repo_returns_json(sample_finding: Finding) -> None:
    """Assert scan_repo returns a valid JSON report with findings and cache_dir."""
    mock_semgrep = MagicMock()
    mock_semgrep.name = "semgrep"
    mock_semgrep.is_available.return_value = True
    mock_semgrep.scan.return_value = [sample_finding]

    mock_gitleaks = MagicMock()
    mock_gitleaks.name = "gitleaks"
    mock_gitleaks.is_available.return_value = False

    with (
        patch("verix.mcp.server.SemgrepScanner", return_value=mock_semgrep),
        patch("verix.mcp.server.GitleaksScanner", return_value=mock_gitleaks),
        patch("verix.mcp.server.save_scan_cache") as mock_save,
        patch("verix.mcp.server.process_findings", return_value=[sample_finding]),
    ):
        result = scan_repo(root_dir="/tmp", severity="medium")

    data = json.loads(result)
    assert "findings" in data
    assert data["total"] == 1
    assert data["scanners_used"] == ["semgrep"]
    assert data["cache_dir"] == "/tmp/.verix"
    mock_save.assert_called_once_with([sample_finding], cache_dir="/tmp/.verix")


def test_scan_repo_returns_error_when_no_scanners() -> None:
    """Assert scan_repo returns an error when no scanners are available."""
    mock_semgrep = MagicMock()
    mock_semgrep.is_available.return_value = False
    mock_gitleaks = MagicMock()
    mock_gitleaks.is_available.return_value = False

    with (
        patch("verix.mcp.server.SemgrepScanner", return_value=mock_semgrep),
        patch("verix.mcp.server.GitleaksScanner", return_value=mock_gitleaks),
    ):
        result = scan_repo(root_dir="/tmp")

    data = json.loads(result)
    assert "error" in data


def test_scan_repo_returns_error_on_invalid_severity() -> None:
    """Assert scan_repo returns an error for an invalid severity string."""
    result = scan_repo(root_dir="/tmp", severity="extreme")
    data = json.loads(result)
    assert "error" in data


def test_scan_repo_uses_explicit_cache_dir(sample_finding: Finding) -> None:
    """Assert scan_repo uses the provided cache_dir and returns it."""
    mock_semgrep = MagicMock()
    mock_semgrep.name = "semgrep"
    mock_semgrep.is_available.return_value = True
    mock_semgrep.scan.return_value = [sample_finding]

    mock_gitleaks = MagicMock()
    mock_gitleaks.name = "gitleaks"
    mock_gitleaks.is_available.return_value = False

    with (
        patch("verix.mcp.server.SemgrepScanner", return_value=mock_semgrep),
        patch("verix.mcp.server.GitleaksScanner", return_value=mock_gitleaks),
        patch("verix.mcp.server.save_scan_cache") as mock_save,
        patch("verix.mcp.server.process_findings", return_value=[sample_finding]),
    ):
        result = scan_repo(root_dir="/tmp", severity="medium", cache_dir="/custom/.verix")

    data = json.loads(result)
    assert data["cache_dir"] == "/custom/.verix"
    mock_save.assert_called_once_with([sample_finding], cache_dir="/custom/.verix")


def test_scan_file_returns_json_and_cache_dir(sample_finding: Finding) -> None:
    """Assert scan_file returns findings and the default cache_dir."""
    mock_semgrep = MagicMock()
    mock_semgrep.name = "semgrep"
    mock_semgrep.is_available.return_value = True
    mock_semgrep.scan.return_value = [sample_finding]

    mock_gitleaks = MagicMock()
    mock_gitleaks.name = "gitleaks"
    mock_gitleaks.is_available.return_value = False

    with (
        patch("verix.mcp.server.Path.exists", return_value=True),
        patch("verix.mcp.server.SemgrepScanner", return_value=mock_semgrep),
        patch("verix.mcp.server.GitleaksScanner", return_value=mock_gitleaks),
        patch("verix.mcp.server.save_scan_cache") as mock_save,
        patch("verix.mcp.server.process_findings", return_value=[sample_finding]),
    ):
        result = scan_file(file_path="/tmp/app.py", severity="medium")

    data = json.loads(result)
    assert data["total"] == 1
    assert data["cache_dir"] == "/tmp/.verix"
    mock_save.assert_called_once_with([sample_finding], cache_dir="/tmp/.verix")


def test_scan_diff_returns_json_and_cache_dir(sample_finding: Finding) -> None:
    """Assert scan_diff returns findings and the default cache_dir."""
    mock_semgrep = MagicMock()
    mock_semgrep.name = "semgrep"
    mock_semgrep.is_available.return_value = True
    mock_semgrep.scan.return_value = [sample_finding]

    mock_gitleaks = MagicMock()
    mock_gitleaks.name = "gitleaks"
    mock_gitleaks.is_available.return_value = False

    with (
        patch("verix.mcp.server.get_changed_files", return_value=["src/app.py"]),
        patch("verix.mcp.server.SemgrepScanner", return_value=mock_semgrep),
        patch("verix.mcp.server.GitleaksScanner", return_value=mock_gitleaks),
        patch("verix.mcp.server.save_scan_cache") as mock_save,
        patch("verix.mcp.server.process_findings", return_value=[sample_finding]),
    ):
        result = scan_diff(root_dir="/repo", severity="medium")

    data = json.loads(result)
    assert data["total"] == 1
    assert data["cache_dir"] == "/repo/.verix"
    mock_save.assert_called_once_with([sample_finding], cache_dir="/repo/.verix")


def test_get_findings_returns_error_when_no_cache() -> None:
    """Assert get_findings returns an error when no cache exists."""
    with patch(
        "verix.mcp.server.load_scan_cache",
        side_effect=FileNotFoundError,
    ):
        result = get_findings()

    data = json.loads(result)
    assert "error" in data


def test_get_findings_returns_findings(sample_finding: Finding) -> None:
    """Assert get_findings returns a valid JSON report with cached findings."""
    finding2 = sample_finding.model_copy(update={"vx_id": "VX-0002", "severity": Severity.MEDIUM})
    with patch(
        "verix.mcp.server.load_scan_cache",
        return_value=[sample_finding, finding2],
    ):
        result = get_findings()

    data = json.loads(result)
    assert data["total"] == 2
    assert data["by_severity"]["high"] == 1
    assert data["by_severity"]["medium"] == 1
