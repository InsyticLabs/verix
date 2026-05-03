from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from verix.git.diff import get_changed_files


class FakePath:
    """A fake Path that always claims to exist."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)

    def __truediv__(self, other: str) -> FakePath:
        return type(self)(str(self._path / other))

    def exists(self) -> bool:
        return True

    def absolute(self) -> Path:
        return self._path.absolute()

    def __str__(self) -> str:
        return str(self._path)


class FakePathWithMissing(FakePath):
    """A fake Path where 'deleted.py' does not exist."""

    def exists(self) -> bool:
        return self._path.name != "deleted.py"


def test_get_changed_files_staged_only():
    """get_changed_files with staged_only=True returns only staged files."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "src/app.py\n"

    with patch("verix.git.diff.subprocess.run", return_value=mock_result) as mock_run:
        with patch("verix.git.diff.Path", side_effect=FakePath):
            result = get_changed_files("/repo", staged_only=True)

    assert mock_run.call_count == 1
    call_args = mock_run.call_args
    assert call_args[0][0] == ["git", "diff", "--staged", "--name-only"]
    assert call_args.kwargs["capture_output"] is True
    assert call_args.kwargs["text"] is True
    assert call_args.kwargs["timeout"] == 120
    assert call_args.kwargs["check"] is False
    assert result == [str(Path("/repo").absolute() / "src/app.py")]


def test_get_changed_files_both_staged_and_unstaged():
    """get_changed_files with staged_only=False merges staged and unstaged files."""
    staged_result = MagicMock()
    staged_result.returncode = 0
    staged_result.stdout = "src/app.py\n"

    unstaged_result = MagicMock()
    unstaged_result.returncode = 0
    unstaged_result.stdout = "src/new.py\n"

    with patch(
        "verix.git.diff.subprocess.run", side_effect=[staged_result, unstaged_result]
    ) as mock_run:
        with patch("verix.git.diff.Path", side_effect=FakePath):
            result = get_changed_files("/repo", staged_only=False)

    assert mock_run.call_count == 2
    assert result == [
        str(Path("/repo").absolute() / "src/app.py"),
        str(Path("/repo").absolute() / "src/new.py"),
    ]


def test_get_changed_files_returns_empty_on_failure():
    """get_changed_files returns empty list when all git diff commands fail."""
    with patch(
        "verix.git.diff.subprocess.run",
        side_effect=subprocess.SubprocessError("git not found"),
    ):
        result = get_changed_files("/repo", staged_only=True)

    assert result == []


def test_get_changed_files_ignores_nonexistent_paths():
    """get_changed_files skips paths that do not exist on disk."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "src/app.py\ndeleted.py\n"

    with patch("verix.git.diff.subprocess.run", return_value=mock_result):
        with patch("verix.git.diff.Path", side_effect=FakePathWithMissing):
            result = get_changed_files("/repo", staged_only=True)

    assert len(result) == 1
    assert "deleted.py" not in [Path(p).name for p in result]
