from __future__ import annotations

from pathlib import Path

PRE_COMMIT_HOOK_CONTENT = """#!/bin/sh
# Verix pre-commit security scan
# Installed by: verix hooks install

echo "Verix: scanning staged changes..."

verix scan --diff --staged-only --severity high

if [ $? -ne 0 ]; then
    echo ""
    echo "Verix: high severity findings detected."
    echo "Fix issues or run: verix policy suppress <id> --reason <reason>"
    echo "To skip this check: git commit --no-verify"
    exit 1
fi

echo "Verix: no high severity findings in staged changes."
exit 0
"""

VERIX_MARKER = "# Installed by: verix hooks install"


def get_hooks_dir(root_dir: Path) -> Path:
    """Return the path to the git hooks directory."""
    return root_dir / ".git" / "hooks"


def is_git_repo(root_dir: Path) -> bool:
    """Check whether the given directory is a git repository."""
    return (root_dir / ".git").exists()


def hook_is_installed(root_dir: Path) -> bool:
    """Check whether the Verix pre-commit hook is installed."""
    hook_path = get_hooks_dir(root_dir) / "pre-commit"
    if not hook_path.exists():
        return False
    return VERIX_MARKER in hook_path.read_text()


def install_pre_commit_hook(root_dir: Path, force: bool = False) -> str:
    """Install the Verix pre-commit hook."""
    if not is_git_repo(root_dir):
        raise ValueError("Not a git repository. Cannot install hooks.")

    hook_path = get_hooks_dir(root_dir) / "pre-commit"

    if hook_path.exists() and not force:
        if hook_is_installed(root_dir):
            raise FileExistsError("Verix hook already installed.")
        raise FileExistsError("A pre-commit hook already exists. Use --force to overwrite.")

    get_hooks_dir(root_dir).mkdir(parents=True, exist_ok=True)
    hook_path.write_text(PRE_COMMIT_HOOK_CONTENT)
    hook_path.chmod(0o755)
    return str(hook_path)


def uninstall_pre_commit_hook(root_dir: Path) -> str:
    """Remove the Verix pre-commit hook."""
    hook_path = get_hooks_dir(root_dir) / "pre-commit"
    if not hook_path.exists():
        raise FileNotFoundError("No pre-commit hook found.")
    if VERIX_MARKER not in hook_path.read_text():
        raise ValueError("Pre-commit hook was not installed by Verix. Will not remove it.")
    hook_path.unlink()
    return str(hook_path)


def hook_status(root_dir: Path) -> dict:
    """Return the status of Verix git hooks."""
    hooks_dir = get_hooks_dir(root_dir)
    pre_commit_path = hooks_dir / "pre-commit"
    return {
        "is_git_repo": is_git_repo(root_dir),
        "hooks_dir": str(hooks_dir),
        "pre_commit_installed": hook_is_installed(root_dir),
        "pre_commit_path": str(pre_commit_path) if pre_commit_path.exists() else None,
    }
