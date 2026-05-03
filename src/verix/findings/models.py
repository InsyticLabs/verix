from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Location(BaseModel):
    """Source code location of a security finding."""

    model_config = ConfigDict(frozen=True)

    path: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None


class FindingStatus(StrEnum):
    """Lifecycle status of a security finding."""

    OPEN = "open"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"
    UNKNOWN = "unknown"


class ScannerType(StrEnum):
    """Category of security scanner."""

    SAST = "sast"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    POLICY = "policy"


class ScannerMetadata(BaseModel):
    """Metadata about the scanner that produced a finding."""

    model_config = ConfigDict(frozen=True)

    tool: str
    tool_version: str | None = None
    scanner_type: ScannerType
    rule_id: str
    raw_severity: str | None = None


class Finding(BaseModel):
    """Normalized security finding produced by any scanner."""

    model_config = ConfigDict(frozen=True)

    vx_id: str = Field(..., pattern=r"^VX-\d{4}$")
    scanner: ScannerMetadata
    fingerprint: str = Field(..., description="Stable hash for deduplication across scans")
    message: str
    severity: Severity
    location: Location
    evidence: str | None = None
    raw_finding: dict[str, Any]
    metadata: dict[str, Any] | None = None
    status: FindingStatus = FindingStatus.OPEN

    def with_severity(self, severity: Severity) -> Finding:
        """Return a new Finding with updated severity."""
        return self.model_copy(update={"severity": severity})

    def with_redacted_evidence(self, evidence: str | None) -> Finding:
        """Return a new Finding with redacted evidence (first 4 chars + ****)."""
        if evidence is None:
            return self.model_copy(update={"evidence": None})
        redacted = evidence[:4] + "****"
        return self.model_copy(update={"evidence": redacted})

    def with_redacted_raw(self, raw_finding: dict[str, Any]) -> Finding:
        """Return a new Finding with an updated raw scanner dict."""
        return self.model_copy(update={"raw_finding": raw_finding})
