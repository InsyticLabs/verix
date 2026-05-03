from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"


def _semgrep_available() -> bool:
    """Return True if semgrep is installed."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False


@pytest.mark.skipif(not _semgrep_available(), reason="semgrep not installed")
def test_scan_finds_sql_injection_and_eval() -> None:
    """Smoke test: run verix scan against vulnerable-app and assert findings."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "verix.cli",
            "scan",
            "--json",
            "--severity",
            "info",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(EXAMPLES_DIR),
    )

    assert result.returncode == 0, result.stderr

    report = json.loads(result.stdout)
    findings = report.get("findings", [])
    assert findings, "Expected at least one finding from vulnerable-app"

    messages = " ".join(f.get("message", "") for f in findings).lower()
    rule_ids = " ".join(f.get("scanner", {}).get("rule_id", "") for f in findings).lower()

    assert "sql" in messages or "sql" in rule_ids, (
        f"Expected SQL injection finding, got: {messages!r} {rule_ids!r}"
    )
    assert "eval" in messages or "eval" in rule_ids, (
        f"Expected eval finding, got: {messages!r} {rule_ids!r}"
    )
