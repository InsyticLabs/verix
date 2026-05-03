from __future__ import annotations

from collections import defaultdict

from verix.findings.models import Finding, Severity

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by fingerprint, keeping the highest severity."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.fingerprint].append(finding)

    index_map = {id(f): i for i, f in enumerate(findings)}

    kept: list[Finding] = []
    for finding in findings:
        group = groups.get(finding.fingerprint)
        if group is None:
            continue
        best = min(
            group,
            key=lambda f: (
                SEVERITY_RANK[f.severity],
                not _has_metadata(f),
                index_map[id(f)],
            ),
        )
        kept.append(best)
        del groups[finding.fingerprint]

    return kept


def _has_metadata(finding: Finding) -> bool:
    """Return True if finding metadata contains non-empty cwe or owasp."""
    if finding.metadata is None:
        return False
    return bool(finding.metadata.get("cwe")) or bool(finding.metadata.get("owasp"))
