from __future__ import annotations

from verix.findings.models import Finding


def explain_finding(finding: Finding) -> str:
    """Return a human-readable explanation of a finding."""
    raise NotImplementedError("explain_finding is not yet implemented.")
