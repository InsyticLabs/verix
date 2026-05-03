from __future__ import annotations

import subprocess
from pathlib import Path


def get_changed_files(root_dir: str, staged_only: bool = False) -> list[str]:
    """Return a list of files changed in the current git working tree."""
    cwd = Path(root_dir)
    files: set[str] = set()
    any_success = False

    commands: tuple[list[str], ...]
    if staged_only:
        commands = (["git", "diff", "--staged", "--name-only"],)
    else:
        commands = (
            ["git", "diff", "--staged", "--name-only"],
            ["git", "diff", "--name-only"],
        )

    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=cwd,
                check=False,
            )
            if result.returncode == 0:
                any_success = True
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if line:
                        path = cwd / line
                        if path.exists():
                            files.add(str(path.absolute()))
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue

    if not any_success:
        return []

    return sorted(files)
