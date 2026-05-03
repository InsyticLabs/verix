from __future__ import annotations

from pathlib import Path

import pytest

from verix.findings.models import Finding, Location, ScannerMetadata, ScannerType, Severity
from verix.fix.context import FixContext, extract_fix_context, format_fix_prompt


def _make_finding(path: str, line_start: int, line_end: int | None = None) -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="test-rule",
        ),
        fingerprint="abc123",
        message="Test finding",
        severity=Severity.HIGH,
        location=Location(
            path=path,
            line_start=line_start,
            line_end=line_end,
        ),
        raw_finding={},
    )


def test_extract_fix_context_reads_file(tmp_path: Path) -> None:
    """extract_fix_context reads file and extracts correct lines."""
    file = tmp_path / "test.py"
    lines = [f"line {i}" for i in range(1, 31)]
    file.write_text("\n".join(lines))
    finding = _make_finding(str(file), 15)
    ctx = extract_fix_context(finding)
    assert "line 15" in ctx.vulnerable_lines
    assert ctx.context_before
    assert ctx.context_after


def test_extract_fix_context_clamps_to_file_bounds(tmp_path: Path) -> None:
    """extract_fix_context clamps context to file boundaries."""
    file = tmp_path / "test.py"
    file.write_text("line 1\nline 2\nline 3\nline 4\nline 5")
    finding = _make_finding(str(file), 2)
    ctx = extract_fix_context(finding, context_lines=10)
    assert "line 1" in ctx.context_before
    assert "line 5" in ctx.context_after
    assert ctx.vulnerable_lines == "line 2"


def test_extract_fix_context_detects_language(tmp_path: Path) -> None:
    """extract_fix_context detects language from file extension."""
    file = tmp_path / "test.py"
    file.write_text("x = 1")
    finding = _make_finding(str(file), 1)
    ctx = extract_fix_context(finding)
    assert ctx.language == "python"


def test_extract_fix_context_raises_when_file_missing(tmp_path: Path) -> None:
    """extract_fix_context raises FileNotFoundError for missing files."""
    finding = _make_finding(str(tmp_path / "missing.py"), 1)
    with pytest.raises(FileNotFoundError):
        extract_fix_context(finding)


def test_format_fix_prompt_contains_finding_id() -> None:
    """format_fix_prompt includes the finding ID."""
    ctx = FixContext(
        finding_id="VX-0001",
        file_path="test.py",
        language="python",
        vulnerable_lines="x = 1",
        context_before="",
        context_after="",
        rule_id="test-rule",
        message="Test message",
        severity="high",
        cwe=[],
        owasp=[],
    )
    prompt = format_fix_prompt(ctx)
    assert "VX-0001" in prompt


def test_format_fix_prompt_marks_vulnerable_lines() -> None:
    """format_fix_prompt marks vulnerable lines with >>>."""
    ctx = FixContext(
        finding_id="VX-0001",
        file_path="test.py",
        language="python",
        vulnerable_lines="x = 1",
        context_before="",
        context_after="",
        rule_id="test-rule",
        message="Test message",
        severity="high",
        cwe=[],
        owasp=[],
    )
    prompt = format_fix_prompt(ctx)
    assert ">>>" in prompt
