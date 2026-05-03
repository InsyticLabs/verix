from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from verix.findings.models import Finding, ScannerType, Severity
from verix.scanners.base import ScanRequest
from verix.scanners.gitleaks import GitleaksScanner


@pytest.fixture
def gitleaks_single_finding() -> str:
    """Return a Gitleaks JSON stdout with a single finding."""
    return """[
  {
    "RuleID": "github-pat",
    "Fingerprint": "abc123:fpath:github-pat:5",
    "File": "config.py",
    "StartLine": 5,
    "EndLine": 5,
    "Secret": "test_secret_value_123",
    "Match": "test_secret_value_123"
  }
]"""


def _mock_path(gitleaks_single_finding: str):
    """Return a mock Path class that reads the fixture text."""
    mock_path_cls = MagicMock()
    mock_path_instance = MagicMock()
    mock_path_instance.read_text.return_value = gitleaks_single_finding
    mock_path_cls.return_value = mock_path_instance
    return mock_path_cls


def test_is_available_returns_true():
    """is_available returns True when Gitleaks responds with exit code 0."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    assert scanner.is_available() is True


def test_is_available_returns_true_on_exit_code_1():
    """is_available returns True when Gitleaks responds with exit code 1."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    assert scanner.is_available() is True


def test_scan_parses_single_finding(gitleaks_single_finding: str):
    """scan parses a single Gitleaks result into a Finding."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    with patch("verix.scanners.gitleaks.Path", _mock_path(gitleaks_single_finding)):
        request = ScanRequest(root_dir=Path("."))
        findings = scanner.scan(request)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.severity == Severity.HIGH
    assert finding.scanner.tool == "gitleaks"
    assert finding.scanner.scanner_type == ScannerType.SECRET


def test_scan_redacts_secret(gitleaks_single_finding: str):
    """scan redacts secret values in evidence and raw_finding."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    with patch("verix.scanners.gitleaks.Path", _mock_path(gitleaks_single_finding)):
        request = ScanRequest(root_dir=Path("."))
        findings = scanner.scan(request)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence == "test****"
    assert finding.raw_finding["Secret"] == "[REDACTED]"
    assert "test_secret_value_123" not in str(finding.raw_finding)
    assert "test_secret_value_123" not in str(finding.evidence)


def test_scan_returns_empty_on_no_findings():
    """scan returns an empty list when Gitleaks reports no findings."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."))
    findings = scanner.scan(request)

    assert findings == []


def test_scan_raises_on_timeout():
    """scan raises RuntimeError when Gitleaks times out."""
    scanner = GitleaksScanner()
    scanner.run_subprocess = MagicMock(side_effect=subprocess.TimeoutExpired("gitleaks", 120))

    request = ScanRequest(root_dir=Path("."))
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan(request)


def test_scan_uses_protect_staged_for_diff_only():
    """scan uses 'gitleaks protect --staged' when diff_only is True."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."), diff_only=True)
    scanner.scan(request)

    call_args = scanner.run_subprocess.call_args[0][0]
    assert "protect" in call_args
    assert "--staged" in call_args


def test_scan_uses_detect_for_full_scan():
    """scan uses 'gitleaks detect --no-git' for full scans."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."))
    scanner.scan(request)

    call_args = scanner.run_subprocess.call_args[0][0]
    assert "detect" in call_args
    assert "--no-git" in call_args


def test_scan_uses_temp_file_for_report(gitleaks_single_finding: str):
    """scan writes report to a temp file instead of /dev/stdout."""
    scanner = GitleaksScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    with patch("verix.scanners.gitleaks.Path", _mock_path(gitleaks_single_finding)):
        request = ScanRequest(root_dir=Path("."))
        scanner.scan(request)

    call_args = scanner.run_subprocess.call_args[0][0]
    report_path_arg = next(arg for arg in call_args if arg.startswith("--report-path="))
    report_path = report_path_arg.split("=", 1)[1]
    assert "/dev/stdout" not in report_path
    assert report_path.endswith(".json")
