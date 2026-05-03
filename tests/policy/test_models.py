from __future__ import annotations

from datetime import date

from verix.findings.models import Severity
from verix.policy.models import (
    PathExclusion,
    ProjectConfig,
    Rules,
    ScanConfig,
    SeverityOverride,
    Suppression,
    ToolConfig,
    ToolsConfig,
    VerixConfig,
)


def test_verix_config_defaults() -> None:
    """VerixConfig creates with expected default values."""
    config = VerixConfig()

    assert config.version == 1
    assert config.project.name == "unknown"
    assert config.suppressions == []
    assert config.scan.severity_threshold == "medium"
    assert config.tools.semgrep.enabled is True
    assert config.tools.gitleaks.enabled is True


def test_suppression_model_fields() -> None:
    """Suppression stores all fields correctly."""
    suppression = Suppression(
        id="VX-SUPPRESS-001",
        fingerprint="deadbeef12345678",
        rule_id="python.sql-injection",
        file="src/app.py",
        reason="legacy code, not internet-facing",
        added_by="alice",
        expires=date(2025, 12, 31),
        active=True,
    )

    assert suppression.id == "VX-SUPPRESS-001"
    assert suppression.fingerprint == "deadbeef12345678"
    assert suppression.rule_id == "python.sql-injection"
    assert suppression.file == "src/app.py"
    assert suppression.reason == "legacy code, not internet-facing"
    assert suppression.added_by == "alice"
    assert suppression.expires == date(2025, 12, 31)
    assert suppression.active is True


def test_severity_override_model() -> None:
    """SeverityOverride stores rule_id, severity, and reason."""
    override = SeverityOverride(
        rule_id="python.sql-injection",
        severity=Severity.LOW,
        reason="reduced risk in test environment",
    )

    assert override.rule_id == "python.sql-injection"
    assert override.severity == Severity.LOW
    assert override.reason == "reduced risk in test environment"


def test_config_roundtrip() -> None:
    """VerixConfig serializes and validates back identically."""
    config = VerixConfig(
        version=2,
        project=ProjectConfig(name="my-app", language="python"),
        scan=ScanConfig(severity_threshold="high", include=["src/**"]),
        tools=ToolsConfig(
            semgrep=ToolConfig(enabled=False, config="custom.yml"),
        ),
        rules=Rules(
            severity_overrides=[
                SeverityOverride(
                    rule_id="python.sql-injection",
                    severity=Severity.LOW,
                    reason="test",
                ),
            ],
            path_exclusions=[
                PathExclusion(
                    rule_id="python.sql-injection",
                    paths=["tests/**"],
                    reason="test files",
                ),
            ],
        ),
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="abc123",
                rule_id="python.sql-injection",
                file="src/app.py",
                reason="legacy",
            ),
        ],
    )

    data = config.model_dump(mode="json")
    restored = VerixConfig.model_validate(data)

    assert restored.version == config.version
    assert restored.project.name == config.project.name
    assert restored.scan.severity_threshold == config.scan.severity_threshold
    assert restored.tools.semgrep.enabled == config.tools.semgrep.enabled
    assert restored.tools.semgrep.config == config.tools.semgrep.config
    assert len(restored.rules.severity_overrides) == 1
    assert restored.rules.severity_overrides[0].rule_id == "python.sql-injection"
    assert len(restored.rules.path_exclusions) == 1
    assert restored.rules.path_exclusions[0].paths == ["tests/**"]
    assert len(restored.suppressions) == 1
    assert restored.suppressions[0].id == "VX-SUPPRESS-001"
