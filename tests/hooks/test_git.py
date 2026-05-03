from __future__ import annotations

import stat
from pathlib import Path

import pytest

from verix.hooks.git import (
    VERIX_MARKER,
    get_hooks_dir,
    hook_is_installed,
    hook_status,
    install_pre_commit_hook,
    is_git_repo,
    uninstall_pre_commit_hook,
)


def test_is_git_repo_true(tmp_path: Path) -> None:
    """Check that a directory with a .git folder is recognised as a repo."""
    (tmp_path / ".git").mkdir()
    assert is_git_repo(tmp_path) is True


def test_is_git_repo_false(tmp_path: Path) -> None:
    """Check that a plain directory is not recognised as a repo."""
    assert is_git_repo(tmp_path) is False


def test_hook_is_installed_false_when_no_file(tmp_path: Path) -> None:
    """Check that hook_is_installed returns False when no pre-commit file exists."""
    assert hook_is_installed(tmp_path) is False


def test_hook_is_installed_false_when_no_marker(tmp_path: Path) -> None:
    """Check that hook_is_installed returns False when marker is absent."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho hello")
    assert hook_is_installed(tmp_path) is False


def test_hook_is_installed_true_when_marker_present(tmp_path: Path) -> None:
    """Check that hook_is_installed returns True when marker is present."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text(f"#!/bin/sh\n{VERIX_MARKER}")
    assert hook_is_installed(tmp_path) is True


def test_install_pre_commit_hook_creates_file(tmp_path: Path) -> None:
    """Check that installation creates an executable pre-commit hook."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hooks").mkdir()
    path = install_pre_commit_hook(tmp_path)
    hook_path = Path(path)
    assert hook_path.exists()
    assert VERIX_MARKER in hook_path.read_text()
    assert "--staged-only" in hook_path.read_text()
    assert stat.S_IMODE(hook_path.stat().st_mode) == 0o755


def test_install_pre_commit_hook_raises_when_not_git_repo(tmp_path: Path) -> None:
    """Check that installation raises ValueError outside a git repo."""
    with pytest.raises(ValueError, match="Not a git repository"):
        install_pre_commit_hook(tmp_path)


def test_install_pre_commit_hook_raises_when_exists_without_force(tmp_path: Path) -> None:
    """Check that installation raises FileExistsError for existing hook."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho hello")
    with pytest.raises(FileExistsError, match="already exists"):
        install_pre_commit_hook(tmp_path)


def test_install_pre_commit_hook_overwrites_with_force(tmp_path: Path) -> None:
    """Check that --force overwrites a non-Verix pre-commit hook."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho hello")
    install_pre_commit_hook(tmp_path, force=True)
    assert VERIX_MARKER in (hooks_dir / "pre-commit").read_text()


def test_uninstall_pre_commit_hook_removes_file(tmp_path: Path) -> None:
    """Check that uninstallation removes the Verix pre-commit hook."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hooks").mkdir()
    install_pre_commit_hook(tmp_path)
    uninstall_pre_commit_hook(tmp_path)
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_uninstall_pre_commit_hook_raises_when_not_verix(tmp_path: Path) -> None:
    """Check that uninstallation refuses to remove a non-Verix hook."""
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho hello")
    with pytest.raises(ValueError, match="not installed by Verix"):
        uninstall_pre_commit_hook(tmp_path)


def test_hook_status_returns_correct_dict(tmp_path: Path) -> None:
    """Check that hook_status returns the expected dictionary."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hooks").mkdir()
    install_pre_commit_hook(tmp_path)
    status = hook_status(tmp_path)
    assert status["is_git_repo"] is True
    assert status["pre_commit_installed"] is True
    assert status["pre_commit_path"] == str(get_hooks_dir(tmp_path) / "pre-commit")
