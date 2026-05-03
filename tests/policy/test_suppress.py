from __future__ import annotations

from datetime import date, timedelta

from verix.findings.models import (
    Finding,
    Location,
    ScannerMetadata,
    ScannerType,
    Severity,
)
from verix.policy.models import Suppression, VerixConfig
from verix.policy.suppress import (
    add_suppression,
    apply_suppressions,
    next_suppression_id,
    remove_suppression,
)


def _make_finding(vx_id: str, fingerprint: str, rule_id: str, path: str) -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        vx_id=vx_id,
        scanner=ScannerMetadata(
            tool="semgrep",
            scanner_type=ScannerType.SAST,
            rule_id=rule_id,
        ),
        fingerprint=fingerprint,
        message="test",
        severity=Severity.HIGH,
        location=Location(path=path),
        raw_finding={},
    )


def test_next_suppression_id_first() -> None:
    """Return the first suppression ID when config has no suppressions."""
    config = VerixConfig()
    assert next_suppression_id(config) == "VX-SUPPRESS-001"


def test_next_suppression_id_increments() -> None:
    """Increment the suppression ID based on existing count."""
    config = VerixConfig(
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="a",
                rule_id="r1",
                file="f1.py",
                reason="test",
            ),
            Suppression(
                id="VX-SUPPRESS-002",
                fingerprint="b",
                rule_id="r2",
                file="f2.py",
                reason="test",
            ),
        ]
    )
    assert next_suppression_id(config) == "VX-SUPPRESS-003"


def test_add_suppression_returns_new_config() -> None:
    """Adding a suppression returns a new config with one more suppression."""
    finding = _make_finding("VX-0001", "abc123", "rule-x", "src/main.py")
    config = VerixConfig()

    updated = add_suppression(finding, config, "legacy code")

    assert len(updated.suppressions) == 1
    assert len(config.suppressions) == 0


def test_add_suppression_fields() -> None:
    """A new suppression copies finding metadata correctly."""
    finding = _make_finding("VX-0001", "abc123", "rule-x", "src/main.py")
    config = VerixConfig()

    updated = add_suppression(
        finding, config, "legacy code", added_by="alice", expires=date(2025, 12, 31)
    )

    suppression = updated.suppressions[0]
    assert suppression.fingerprint == "abc123"
    assert suppression.rule_id == "rule-x"
    assert suppression.file == "src/main.py"
    assert suppression.reason == "legacy code"
    assert suppression.added_by == "alice"
    assert suppression.expires == date(2025, 12, 31)
    assert suppression.active is True


def test_remove_suppression_removes_by_id() -> None:
    """Removing a suppression drops it from the config without mutating."""
    config = VerixConfig(
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="a",
                rule_id="r1",
                file="f1.py",
                reason="test",
            ),
            Suppression(
                id="VX-SUPPRESS-002",
                fingerprint="b",
                rule_id="r2",
                file="f2.py",
                reason="test",
            ),
        ]
    )

    updated = remove_suppression("VX-SUPPRESS-001", config)

    assert len(updated.suppressions) == 1
    assert updated.suppressions[0].id == "VX-SUPPRESS-002"
    assert len(config.suppressions) == 2


def test_remove_suppression_raises_when_not_found() -> None:
    """Removing an unknown suppression raises ValueError."""
    config = VerixConfig(
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="a",
                rule_id="r1",
                file="f1.py",
                reason="test",
            ),
        ]
    )

    try:
        remove_suppression("VX-SUPPRESS-999", config)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "not found" in str(exc)


def test_apply_suppressions_splits_correctly() -> None:
    """Apply suppressions splits findings into active and suppressed lists."""
    finding_a = _make_finding("VX-0001", "abc", "rule-1", "file.py")
    finding_b = _make_finding("VX-0002", "def", "rule-2", "file.py")

    config = VerixConfig(
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="abc",
                rule_id="rule-1",
                file="file.py",
                reason="known issue",
            ),
        ]
    )

    active, suppressed = apply_suppressions([finding_a, finding_b], config)

    assert len(active) == 1
    assert active[0].vx_id == "VX-0002"
    assert len(suppressed) == 1
    assert suppressed[0].vx_id == "VX-0001"


def test_apply_suppressions_all_active_when_no_policy() -> None:
    """All findings are active when the policy config has no suppressions."""
    finding = _make_finding("VX-0001", "abc", "rule-1", "file.py")
    config = VerixConfig()

    active, suppressed = apply_suppressions([finding], config)

    assert len(active) == 1
    assert len(suppressed) == 0


def test_apply_suppressions_respects_expiration() -> None:
    """Expired suppressions do not suppress findings."""
    finding = _make_finding("VX-0001", "abc", "rule-1", "file.py")

    config = VerixConfig(
        suppressions=[
            Suppression(
                id="VX-SUPPRESS-001",
                fingerprint="abc",
                rule_id="rule-1",
                file="file.py",
                reason="old",
                expires=date.today() - timedelta(days=1),
            ),
        ]
    )

    active, suppressed = apply_suppressions([finding], config)

    assert len(active) == 1
    assert len(suppressed) == 0
