from __future__ import annotations

from verix.cli import app


def test_cli_app_exists() -> None:
    """Verify the Typer app instance exists."""
    assert app.info.name == "verix"


def test_scan_command_exists() -> None:
    """Verify the scan command is registered."""
    assert "scan" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]


def test_explain_command_exists() -> None:
    """Verify the explain command is registered."""
    assert "explain" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]


def test_report_command_exists() -> None:
    """Verify the report command is registered."""
    assert "report" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]


def test_init_command_exists() -> None:
    """Verify the init command is registered."""
    assert "init" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]


def test_fix_command_exists() -> None:
    """Verify the fix command is registered."""
    assert "fix" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]


def test_verify_command_exists() -> None:
    """Verify the verify command is registered."""
    assert "verify" in [
        getattr(cmd, "name", None) or cmd.callback.__name__ for cmd in app.registered_commands
    ]
