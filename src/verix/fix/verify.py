from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from verix.findings.models import Finding, ScannerType
from verix.findings.normalize import process_findings
from verix.scanners.base import ScanRequest
from verix.scanners.gitleaks import GitleaksScanner
from verix.scanners.semgrep import SemgrepScanner


class VerifyOutcome(StrEnum):
    """Possible outcomes of a fix verification scan."""

    FIXED = "fixed"
    STILL_PRESENT = "still_present"
    INCONCLUSIVE = "inconclusive"


class VerifyResult(BaseModel):
    """Result of verifying whether a finding has been fixed."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    file_path: str
    outcome: VerifyOutcome
    message: str
    remaining_findings: list[Finding]


def verify_finding(finding: Finding) -> VerifyResult:
    """Re-scan the target file to determine if the finding has been fixed."""
    scanner_type = finding.scanner.scanner_type

    scanner_class: type[SemgrepScanner] | type[GitleaksScanner] | None = None
    if scanner_type == ScannerType.SAST:
        scanner_class = SemgrepScanner
    elif scanner_type == ScannerType.SECRET:
        scanner_class = GitleaksScanner

    if scanner_class is None:
        return VerifyResult(
            finding_id=finding.vx_id,
            file_path=finding.location.path,
            outcome=VerifyOutcome.INCONCLUSIVE,
            message="No scanner available for this finding type.",
            remaining_findings=[],
        )

    scanner = scanner_class()
    if not scanner.is_available():
        return VerifyResult(
            finding_id=finding.vx_id,
            file_path=finding.location.path,
            outcome=VerifyOutcome.INCONCLUSIVE,
            message=f"Scanner {scanner.name} is not available.",
            remaining_findings=[],
        )

    request = ScanRequest(
        root_dir=Path(finding.location.path).parent,
        files=[finding.location.path],
        diff_only=False,
    )

    raw_results = scanner.scan(request)
    processed = process_findings(raw_results)

    matching = [f for f in processed if f.fingerprint == finding.fingerprint]
    if matching:
        return VerifyResult(
            finding_id=finding.vx_id,
            file_path=finding.location.path,
            outcome=VerifyOutcome.STILL_PRESENT,
            message=f"Finding still present: {len(matching)} match(es) found.",
            remaining_findings=matching,
        )

    return VerifyResult(
        finding_id=finding.vx_id,
        file_path=finding.location.path,
        outcome=VerifyOutcome.FIXED,
        message="Finding no longer detected.",
        remaining_findings=[],
    )
