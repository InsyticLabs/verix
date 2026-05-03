from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from verix.findings.models import (
    Finding,
    FindingStatus,
    Location,
    ScannerMetadata,
    ScannerType,
    Severity,
)
from verix.scanners.base import ScannerAdapter, ScanRequest


class GitleaksScanner(ScannerAdapter):
    """Adapter for Gitleaks secret detection scanner."""

    name = "gitleaks"

    def is_available(self) -> bool:
        """Return True if Gitleaks is installed and callable."""
        try:
            result = self.run_subprocess(["gitleaks", "version"])
            return result.returncode in (0, 1)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return False

    def scan(self, request: ScanRequest) -> list[Finding]:
        """Run Gitleaks against the request and return raw findings."""
        report_path: str | None = None

        if request.diff_only:
            command = [
                "gitleaks",
                "protect",
                "--staged",
                "--report-format=json",
            ]
        else:
            command = [
                "gitleaks",
                "detect",
                "--report-format=json",
                "--no-git",
            ]

        try:
            with tempfile.NamedTemporaryFile(
                mode="w+", suffix=".json", delete=False
            ) as tmp:
                report_path = tmp.name

            command.append(f"--report-path={report_path}")
            command.append("--source=" + str(request.root_dir))

            try:
                proc = self.run_subprocess(command)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Gitleaks timed out after 120s") from exc

            if proc.returncode == 0:
                return []

            if proc.returncode >= 2:
                raise RuntimeError(proc.stderr)

            stdout = Path(report_path).read_text(encoding="utf-8")
            if not stdout:
                return []

            try:
                findings = json.loads(stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(proc.stderr) from exc

            if not isinstance(findings, list):
                return []

            return [self._map_finding(finding) for finding in findings]
        finally:
            if report_path is not None:
                Path(report_path).unlink(missing_ok=True)

    def _map_finding(self, finding: dict[str, Any]) -> Finding:
        """Map a single Gitleaks JSON finding to a Finding."""
        rule_id = finding["RuleID"]
        file_path = finding["File"]
        start_line = finding.get("StartLine")

        fingerprint = finding.get("Fingerprint", "")
        if not fingerprint:
            fingerprint_input = f"{rule_id}:{file_path}:{start_line}"
            fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]

        secret = finding.get("Secret", "")
        evidence = self._redact_secret(secret)

        raw_finding = dict(finding)
        raw_finding["Secret"] = "[REDACTED]"

        match = finding.get("Match")
        metadata: dict[str, Any] | None = None
        if match is not None:
            raw_finding["Match"] = "[REDACTED]"
            metadata = {"match": self._redact_secret(match)}

        return Finding(
            vx_id="VX-0000",
            fingerprint=fingerprint,
            scanner=ScannerMetadata(
                tool="gitleaks",
                tool_version=None,
                scanner_type=ScannerType.SECRET,
                rule_id=rule_id,
                raw_severity="HIGH",
            ),
            message=f"Secret detected: {rule_id}",
            severity=Severity.HIGH,
            location=Location(
                path=file_path,
                line_start=start_line,
                line_end=finding.get("EndLine"),
                column_start=None,
                column_end=None,
            ),
            evidence=evidence,
            raw_finding=raw_finding,
            metadata=metadata,
            status=FindingStatus.OPEN,
        )

    @staticmethod
    def _redact_secret(value: str) -> str:
        """Redact a secret value to first 4 chars + ****."""
        if len(value) > 4:
            return value[:4] + "****"
        return "****"
