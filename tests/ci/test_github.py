from __future__ import annotations

from pathlib import Path

from verix.ci.github import generate_github_workflow, write_github_workflow


def test_generate_github_workflow_contains_verix_scan() -> None:
    """Generated workflow should contain the verix scan command."""
    result = generate_github_workflow()
    assert "verix scan" in result


def test_generate_github_workflow_contains_sarif_upload_by_default() -> None:
    """Generated workflow should include SARIF upload step by default."""
    result = generate_github_workflow()
    assert "upload-sarif" in result


def test_generate_github_workflow_no_sarif_when_disabled() -> None:
    """Generated workflow should omit SARIF upload step when disabled."""
    result = generate_github_workflow(sarif_upload=False)
    assert "upload-sarif" not in result


def test_generate_github_workflow_uses_block_on_severity() -> None:
    """Generated workflow should use the specified block-on severity."""
    result = generate_github_workflow(block_on_severity="critical")
    assert "--severity critical" in result


def test_generate_github_workflow_uses_python_version() -> None:
    """Generated workflow should use the specified Python version."""
    result = generate_github_workflow(python_version="3.13")
    assert "3.13" in result


def test_write_github_workflow_creates_file(tmp_path: Path) -> None:
    """write_github_workflow should create the workflow file."""
    write_github_workflow(tmp_path)
    file_path = tmp_path / ".github" / "workflows" / "verix.yml"
    assert file_path.exists()
    assert "Verix" in file_path.read_text()


def test_write_github_workflow_returns_path(tmp_path: Path) -> None:
    """write_github_workflow should return the path to the created file."""
    result = write_github_workflow(tmp_path)
    assert result.endswith("verix.yml")
