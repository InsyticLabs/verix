from __future__ import annotations

import hashlib
import json
import subprocess
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


class SemgrepScanner(ScannerAdapter):
    """Adapter for Semgrep static analysis scanner."""

    name = "semgrep"

    def is_available(self) -> bool:
        """Return True if Semgrep is installed and callable."""
        try:
            result = self.run_subprocess(["semgrep", "--version"])
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return False

    def scan(self, request: ScanRequest) -> list[Finding]:
        """Run Semgrep against the request and return raw findings."""
        command = ["semgrep", "scan", "--config=auto", "--json", "--quiet"]

        if request.files:
            command.extend(request.files)
        else:
            command.append(str(request.root_dir))

        try:
            proc = self.run_subprocess(command)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Semgrep timed out after 120s") from exc

        if proc.returncode >= 2:
            raise RuntimeError(proc.stderr)

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(proc.stderr) from exc

        results = data.get("results", [])
        if not results:
            return []

        return [self._map_result(result) for result in results]

    def _map_result(self, result: dict[str, Any]) -> Finding:
        """Map a single Semgrep JSON result to a Finding."""
        rule_id = result["check_id"]
        file_path = result["path"]
        start_line = result["start"]["line"]

        raw_severity = result["extra"].get("severity", "WARNING")
        severity = self._map_severity(raw_severity)

        fingerprint_input = f"{rule_id}:{file_path}:{start_line}"
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]

        evidence = result["extra"].get("lines", "")
        if evidence:
            evidence = evidence.strip()
            if len(evidence) > 500:
                evidence = evidence[:500]

        metadata: dict[str, list[str]] | None = None
        raw_metadata = result["extra"].get("metadata")
        if raw_metadata is not None:
            metadata = {
                "cwe": self._coerce_to_list(raw_metadata.get("cwe")),
                "owasp": self._coerce_to_list(raw_metadata.get("owasp")),
            }

        return Finding(
            vx_id="VX-0000",
            fingerprint=fingerprint,
            scanner=ScannerMetadata(
                tool="semgrep",
                tool_version=None,
                scanner_type=ScannerType.SAST,
                rule_id=rule_id,
                raw_severity=raw_severity,
            ),
            message=result["extra"].get("message", ""),
            severity=severity,
            location=Location(
                path=file_path,
                line_start=start_line,
                line_end=result["end"].get("line"),
                column_start=result["start"].get("col"),
                column_end=result["end"].get("col"),
            ),
            evidence=evidence,
            raw_finding=result,
            metadata=metadata,
            status=FindingStatus.OPEN,
        )

    @staticmethod
    def _map_severity(raw_severity: str) -> Severity:
        """Map Semgrep severity string to Verix Severity."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return mapping.get(raw_severity, Severity.MEDIUM)

    @staticmethod
    def _coerce_to_list(value: Any) -> list[str]:
        """Coerce a string or list to a list of strings."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return []
