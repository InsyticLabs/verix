from __future__ import annotations

from verix.cli import policy_app


def test_policy_diff_command_exists() -> None:
    """Assert the policy diff command is registered."""
    command_names = [cmd.name for cmd in policy_app.registered_commands]
    assert "diff" in command_names
