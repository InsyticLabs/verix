from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import yaml

from verix.findings.models import (
    Finding,
    Location,
    ScannerMetadata,
    ScannerType,
    Severity,
)
from verix.policy.loader import is_suppressed, load_policy, save_policy
from verix.policy.models import ProjectConfig, Suppression, VerixConfig


def test_load_policy_returns_defaults_when_file_missing() -> None:
    """load_policy returns default VerixConfig when file does not exist."""
    config = load_policy("nonexistent.yaml")

    assert config == VerixConfig()
    assert config.version == 1
    assert config.project.name == "unknown"


def test_load_policy_parses_yaml(tmp_path: Path) -> None:
    """load_policy parses a valid verix.yaml correctly."""
    config_file = tmp_path / "verix.yaml"
    config_file.write_text(
        "project:\n  name: my-project\n  language: python\n",
        encoding="utf-8",
    )

    config = load_policy(str(config_file))

    assert config.project.name == "my-project"
    assert config.project.language == "python"


def test_save_policy_writes_yaml(tmp_path: Path) -> None:
    """save_policy serializes VerixConfig to valid YAML."""
    config = VerixConfig(
        version=2,
        project=ProjectConfig(name="test-project", language="python"),
    )
    config_file = tmp_path / "verix.yaml"

    save_policy(config, str(config_file))

    content = config_file.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert isinstance(data, dict)
    assert data["version"] == 2
    assert data["project"]["name"] == "test-project"
    assert data["project"]["language"] == "python"


def test_is_suppressed_returns_true_on_match() -> None:
    """is_suppressed returns True when all three criteria match."""
    finding = Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="python.sql-injection",
        ),
        fingerprint="abc123def4567890",
        message="Possible SQL injection",
        severity=Severity.HIGH,
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
    )
    suppression = Suppression(
        id="VX-SUPPRESS-001",
        fingerprint="abc123def4567890",
        rule_id="python.sql-injection",
        file="src/app.py",
        reason="legacy",
    )
    config = VerixConfig(suppressions=[suppression])

    assert is_suppressed(finding, config) is True


def test_is_suppressed_returns_false_on_fingerprint_mismatch() -> None:
    """is_suppressed returns False when fingerprint differs."""
    finding = Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="python.sql-injection",
        ),
        fingerprint="abc123def4567890",
        message="Possible SQL injection",
        severity=Severity.HIGH,
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
    )
    suppression = Suppression(
        id="VX-SUPPRESS-001",
        fingerprint="mismatch12345678",
        rule_id="python.sql-injection",
        file="src/app.py",
        reason="legacy",
    )
    config = VerixConfig(suppressions=[suppression])

    assert is_suppressed(finding, config) is False


def test_is_suppressed_returns_false_when_expired() -> None:
    """is_suppressed returns False for an expired suppression."""
    finding = Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="python.sql-injection",
        ),
        fingerprint="abc123def4567890",
        message="Possible SQL injection",
        severity=Severity.HIGH,
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
    )
    suppression = Suppression(
        id="VX-SUPPRESS-001",
        fingerprint="abc123def4567890",
        rule_id="python.sql-injection",
        file="src/app.py",
        reason="legacy",
        expires=date.today() - timedelta(days=1),
    )
    config = VerixConfig(suppressions=[suppression])

    assert is_suppressed(finding, config) is False


def test_is_suppressed_returns_false_when_inactive() -> None:
    """is_suppressed returns False for an inactive suppression."""
    finding = Finding(
        vx_id="VX-0001",
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id="python.sql-injection",
        ),
        fingerprint="abc123def4567890",
        message="Possible SQL injection",
        severity=Severity.HIGH,
        location=Location(path="src/app.py", line_start=10),
        raw_finding={},
    )
    suppression = Suppression(
        id="VX-SUPPRESS-001",
        fingerprint="abc123def4567890",
        rule_id="python.sql-injection",
        file="src/app.py",
        reason="legacy",
        active=False,
    )
    config = VerixConfig(suppressions=[suppression])

    assert is_suppressed(finding, config) is False
