from __future__ import annotations

from verix.findings.dedupe import SEVERITY_RANK, deduplicate
from verix.findings.fingerprint import generate_fingerprint
from verix.findings.models import Finding


def normalize_findings(findings: list[Finding], start_id: int = 1) -> list[Finding]:
    """Normalize findings: regenerate fingerprints, sort by severity, assign IDs."""
    with_fps: list[Finding] = []
    for finding in findings:
        new_fp = generate_fingerprint(
            finding.scanner.tool,
            finding.scanner.rule_id,
            finding.location.path,
            finding.location.line_start,
        )
        with_fps.append(finding.model_copy(update={"fingerprint": new_fp}))

    with_fps.sort(key=lambda f: SEVERITY_RANK[f.severity])

    return [
        f.model_copy(update={"vx_id": f"VX-{n:04d}"})
        for n, f in enumerate(with_fps, start=start_id)
    ]


def process_findings(raw_findings: list[Finding]) -> list[Finding]:
    """Deduplicate then normalize findings."""
    return normalize_findings(deduplicate(raw_findings))
