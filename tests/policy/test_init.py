from __future__ import annotations

from pathlib import Path

from verix.policy.init import (
    detect_project,
    generate_gitleaksignore,
    generate_semgrepignore,
    run_policy_init,
)


def test_detect_project_python(tmp_path: Path) -> None:
    """Detect python project with typer framework."""
    (tmp_path / "pyproject.toml").write_text('[tool.poetry.dependencies]\ntyper = "^0.9"\n')
    assert detect_project(tmp_path) == ("python", "typer")


def test_detect_project_nodejs_nextjs(tmp_path: Path) -> None:
    """Detect nodejs project with nextjs framework."""
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "14.0.0", "react": "^18"}}')
    assert detect_project(tmp_path) == ("nodejs", "nextjs")


def test_detect_project_unknown(tmp_path: Path) -> None:
    """Detect unknown project when no markers exist."""
    assert detect_project(tmp_path) == ("unknown", None)


def test_generate_semgrepignore_python() -> None:
    """Semgrepignore for python includes expected paths."""
    content = generate_semgrepignore("python")
    assert ".venv/" in content
    assert "tests/" in content


def test_generate_gitleaksignore_contains_tests() -> None:
    """Gitleaksignore contains test directory patterns."""
    content = generate_gitleaksignore("python")
    assert "tests/" in content


def test_run_policy_init_creates_files(tmp_path: Path) -> None:
    """run_policy_init creates all three policy files."""
    config, created = run_policy_init(tmp_path)
    assert (tmp_path / "verix.yaml").exists()
    assert (tmp_path / ".semgrepignore").exists()
    assert (tmp_path / ".gitleaksignore").exists()
    assert str(tmp_path / "verix.yaml") in created


def test_run_policy_init_skips_existing_without_force(tmp_path: Path) -> None:
    """run_policy_init skips existing files when force is False."""
    custom = "version: 99\n"
    (tmp_path / "verix.yaml").write_text(custom)
    config, created = run_policy_init(tmp_path, force=False)
    assert (tmp_path / "verix.yaml").read_text() == custom
    assert str(tmp_path / "verix.yaml") not in created


def test_run_policy_init_overwrites_with_force(tmp_path: Path) -> None:
    """run_policy_init overwrites existing files when force is True."""
    (tmp_path / "verix.yaml").write_text("version: 99\n")
    config, created = run_policy_init(tmp_path, force=True)
    assert str(tmp_path / "verix.yaml") in created
    content = (tmp_path / "verix.yaml").read_text()
    assert "version: 1" in content
