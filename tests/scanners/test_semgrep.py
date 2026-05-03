from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from verix.findings.models import Finding, ScannerType, Severity
from verix.scanners.base import ScanRequest
from verix.scanners.semgrep import SemgrepScanner


@pytest.fixture
def semgrep_single_result() -> str:
    """Return a Semgrep JSON stdout with a single finding."""
    return """
    {
      "results": [
        {
          "check_id": "python.sql-injection",
          "path": "src/app.py",
          "start": {"line": 10, "col": 5, "offset": 100},
          "end": {"line": 10, "col": 42, "offset": 137},
          "extra": {
            "message": "Possible SQL injection",
            "severity": "ERROR",
            "lines": "cursor.execute(query)",
            "metadata": {
              "cwe": "CWE-89",
              "owasp": ["A03:2021 - Injection"]
            }
          }
        }
      ],
      "errors": []
    }
    """


def test_is_available_returns_true():
    """is_available returns True when Semgrep responds with exit code 0."""
    scanner = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    assert scanner.is_available() is True


def test_is_available_returns_false_when_not_installed():
    """is_available returns False when Semgrep is not found."""
    scanner = SemgrepScanner()
    scanner.run_subprocess = MagicMock(side_effect=FileNotFoundError)

    assert scanner.is_available() is False


def test_scan_parses_single_result(semgrep_single_result: str):
    """scan parses a single Semgrep result into a Finding."""
    scanner = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = semgrep_single_result
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."))
    findings = scanner.scan(request)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.severity == Severity.HIGH
    assert finding.scanner.tool == "semgrep"
    assert finding.scanner.scanner_type == ScannerType.SAST


def test_scan_returns_empty_on_no_results():
    """scan returns an empty list when Semgrep reports no findings."""
    scanner = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"results": [], "errors": []}'
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."))
    findings = scanner.scan(request)

    assert findings == []


def test_scan_raises_on_timeout():
    """scan raises RuntimeError when Semgrep times out."""
    scanner = SemgrepScanner()
    scanner.run_subprocess = MagicMock(side_effect=subprocess.TimeoutExpired("semgrep", 120))

    request = ScanRequest(root_dir=Path("."))
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan(request)


def test_scan_honors_files_when_diff_only_false(semgrep_single_result: str):
    """scan passes request.files to Semgrep even when diff_only is False."""
    scanner = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = semgrep_single_result
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."), diff_only=False, files=["src/app.py"])
    findings = scanner.scan(request)

    assert len(findings) == 1
    call_args = scanner.run_subprocess.call_args[0][0]
    assert "src/app.py" in call_args
    assert str(request.root_dir) not in call_args


def test_scan_honors_files_when_diff_only_true(semgrep_single_result: str):
    """scan passes request.files to Semgrep when diff_only is True."""
    scanner = SemgrepScanner()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = semgrep_single_result
    mock_result.stderr = ""
    scanner.run_subprocess = MagicMock(return_value=mock_result)

    request = ScanRequest(root_dir=Path("."), diff_only=True, files=["src/app.py"])
    findings = scanner.scan(request)

    assert len(findings) == 1
    call_args = scanner.run_subprocess.call_args[0][0]
    assert "src/app.py" in call_args
    assert str(request.root_dir) not in call_args
