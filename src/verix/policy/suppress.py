from __future__ import annotations

from datetime import date

from verix.findings.models import Finding
from verix.policy.models import Suppression, VerixConfig


def next_suppression_id(config: VerixConfig) -> str:
    """Return the next suppression ID in sequence."""
    count = len(config.suppressions)
    return f"VX-SUPPRESS-{count + 1:03d}"


def add_suppression(
    finding: Finding,
    config: VerixConfig,
    reason: str,
    added_by: str = "unknown",
    expires: date | None = None,
) -> VerixConfig:
    """Add a new suppression for a finding and return an updated config."""
    suppression = Suppression(
        id=next_suppression_id(config),
        fingerprint=finding.fingerprint,
        rule_id=finding.scanner.rule_id,
        file=finding.location.path,
        reason=reason,
        added_by=added_by,
        expires=expires,
        active=True,
    )
    new_suppressions = list(config.suppressions) + [suppression]
    return config.model_copy(update={"suppressions": new_suppressions})


def remove_suppression(
    suppression_id: str,
    config: VerixConfig,
) -> VerixConfig:
    """Remove a suppression by ID and return an updated config."""
    for suppression in config.suppressions:
        if suppression.id == suppression_id:
            new_suppressions = [s for s in config.suppressions if s.id != suppression_id]
            return config.model_copy(update={"suppressions": new_suppressions})

    raise ValueError(f"Suppression {suppression_id} not found")


def apply_suppressions(
    findings: list[Finding],
    config: VerixConfig,
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into active and suppressed lists based on policy."""
    from verix.policy.loader import is_suppressed

    active: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in findings:
        if is_suppressed(finding, config):
            suppressed.append(finding)
        else:
            active.append(finding)

    return active, suppressed
