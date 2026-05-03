from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from verix.cache import load_scan_cache, save_scan_cache
from verix.findings.dedupe import SEVERITY_RANK
from verix.findings.models import Finding, Severity
from verix.findings.normalize import process_findings
from verix.fix.context import extract_fix_context, format_fix_prompt
from verix.fix.verify import verify_finding as _verify_finding
from verix.git.diff import get_changed_files
from verix.policy.loader import load_policy, save_policy
from verix.policy.suppress import add_suppression
from verix.reports.json_report import generate_json_report
from verix.reports.markdown_report import generate_markdown_report
from verix.scanners.base import ScanRequest
from verix.scanners.gitleaks import GitleaksScanner
from verix.scanners.semgrep import SemgrepScanner

mcp = FastMCP("verix")


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Return a dict of severity counts from a list of findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _findings_to_json(
    findings: list[Finding],
    scanners_used: list[str] | None = None,
    cache_dir: str | None = None,
) -> str:
    """Serialize findings to a JSON string report."""
    data: dict = {
        "total": len(findings),
        "by_severity": _severity_counts(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    if scanners_used is not None:
        data["scanners_used"] = scanners_used
    if cache_dir is not None:
        data["cache_dir"] = cache_dir
    return json.dumps(data, indent=2)


def _filter_by_severity(findings: list[Finding], severity: Severity) -> list[Finding]:
    """Return findings with severity rank at or above the threshold."""
    threshold = SEVERITY_RANK[severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= threshold]


@mcp.tool()
def scan_repo(
    root_dir: Annotated[str, Field(description="absolute path to scan")],
    severity: Annotated[str, Field(description="minimum severity threshold")] = "medium",
    cache_dir: Annotated[str, Field(description="cache directory")] = "",
) -> str:
    """Scan the entire repository for security vulnerabilities."""
    try:
        try:
            threshold = Severity[severity.upper()]
        except KeyError:
            return json.dumps({"error": f"Invalid severity: {severity}"}, indent=2)

        scanners = [SemgrepScanner(), GitleaksScanner()]
        available = [s for s in scanners if s.is_available()]
        if not available:
            return json.dumps({"error": "No scanners available"}, indent=2)

        request = ScanRequest(root_dir=Path(root_dir), diff_only=False, files=[])
        raw_findings: list[Finding] = []
        for scanner in available:
            raw_findings.extend(scanner.scan(request))

        findings = process_findings(raw_findings)
        findings = _filter_by_severity(findings, threshold)
        if not cache_dir:
            cache_dir = str(Path(root_dir) / ".verix")
        save_scan_cache(findings, cache_dir=cache_dir)

        return _findings_to_json(
            findings,
            scanners_used=[s.name for s in available],
            cache_dir=cache_dir,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def scan_file(
    file_path: Annotated[str, Field(description="absolute path to file")],
    severity: Annotated[str, Field(description="minimum severity threshold")] = "medium",
    cache_dir: Annotated[str, Field(description="cache directory")] = "",
) -> str:
    """Scan a single file for security vulnerabilities."""
    try:
        try:
            threshold = Severity[severity.upper()]
        except KeyError:
            return json.dumps({"error": f"Invalid severity: {severity}"}, indent=2)

        path = Path(file_path)
        if not path.exists():
            return json.dumps({"error": f"File not found: {file_path}"}, indent=2)

        scanners = [SemgrepScanner(), GitleaksScanner()]
        available = [s for s in scanners if s.is_available()]
        if not available:
            return json.dumps({"error": "No scanners available"}, indent=2)

        request = ScanRequest(
            root_dir=path.parent,
            diff_only=False,
            files=[str(path)],
        )
        raw_findings: list[Finding] = []
        for scanner in available:
            raw_findings.extend(scanner.scan(request))

        findings = process_findings(raw_findings)
        findings = _filter_by_severity(findings, threshold)
        if not cache_dir:
            cache_dir = str(path.parent / ".verix")
        save_scan_cache(findings, cache_dir=cache_dir)

        return _findings_to_json(
            findings,
            scanners_used=[s.name for s in available],
            cache_dir=cache_dir,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def scan_diff(
    root_dir: Annotated[str, Field(description="absolute path to scan")],
    severity: Annotated[str, Field(description="minimum severity threshold")] = "medium",
    cache_dir: Annotated[str, Field(description="cache directory")] = "",
) -> str:
    """Scan only files changed in the current git diff."""
    try:
        try:
            threshold = Severity[severity.upper()]
        except KeyError:
            return json.dumps({"error": f"Invalid severity: {severity}"}, indent=2)

        changed = get_changed_files(root_dir)
        if not changed:
            if not cache_dir:
                cache_dir = str(Path(root_dir) / ".verix")
            return _findings_to_json(
                [],
                scanners_used=[],
                cache_dir=cache_dir,
            )

        scanners = [SemgrepScanner(), GitleaksScanner()]
        available = [s for s in scanners if s.is_available()]
        if not available:
            return json.dumps({"error": "No scanners available"}, indent=2)

        request = ScanRequest(
            root_dir=Path(root_dir),
            diff_only=True,
            files=changed,
        )
        raw_findings: list[Finding] = []
        for scanner in available:
            raw_findings.extend(scanner.scan(request))

        findings = process_findings(raw_findings)
        findings = _filter_by_severity(findings, threshold)
        if not cache_dir:
            cache_dir = str(Path(root_dir) / ".verix")
        save_scan_cache(findings, cache_dir=cache_dir)

        return _findings_to_json(
            findings,
            scanners_used=[s.name for s in available],
            cache_dir=cache_dir,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def get_findings(
    severity: Annotated[str, Field(description="filter by minimum severity")] = "",
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
) -> str:
    """Retrieve findings from the last scan."""
    try:
        findings = load_scan_cache(cache_dir)
        if severity:
            try:
                threshold = Severity[severity.upper()]
            except KeyError:
                return json.dumps({"error": f"Invalid severity: {severity}"}, indent=2)
            findings = _filter_by_severity(findings, threshold)

        return json.dumps(
            {
                "total": len(findings),
                "by_severity": _severity_counts(findings),
                "findings": [f.model_dump(mode="json") for f in findings],
            },
            indent=2,
        )
    except FileNotFoundError:
        return json.dumps(
            {"error": "No scan cache found. Run scan first."},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def explain_finding(
    finding_id: Annotated[str, Field(description="e.g. VX-0001")],
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
) -> str:
    """Get detailed information about a specific finding."""
    try:
        findings = load_scan_cache(cache_dir)
        finding = next((f for f in findings if f.vx_id == finding_id), None)
        if finding is None:
            return json.dumps(
                {"error": f"Finding {finding_id} not found"},
                indent=2,
            )
        return json.dumps(
            {
                "finding_id": finding.vx_id,
                "severity": finding.severity.value,
                "message": finding.message,
                "file": finding.location.path,
                "line_start": finding.location.line_start,
                "line_end": finding.location.line_end,
                "scanner": finding.scanner.tool,
                "rule_id": finding.scanner.rule_id,
                "scanner_type": finding.scanner.scanner_type.value,
                "cwe": finding.metadata.get("cwe", []) if finding.metadata else [],
                "owasp": finding.metadata.get("owasp", []) if finding.metadata else [],
                "evidence": finding.evidence,
                "status": finding.status.value,
            },
            indent=2,
        )
    except FileNotFoundError:
        return json.dumps(
            {"error": "No scan cache found. Run scan first."},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def fix_context(
    finding_id: Annotated[str, Field(description="finding identifier")],
    context_lines: Annotated[int, Field(description="lines of context")] = 10,
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
) -> str:
    """Get fix context for a finding so Claude Code can generate a patch."""
    try:
        findings = load_scan_cache(cache_dir)
        finding = next((f for f in findings if f.vx_id == finding_id), None)
        if finding is None:
            return json.dumps(
                {"error": f"Finding {finding_id} not found"},
                indent=2,
            )
        ctx = extract_fix_context(finding, context_lines)
        prompt = format_fix_prompt(ctx)
        return json.dumps(
            {
                "finding_id": finding_id,
                "language": ctx.language,
                "file_path": ctx.file_path,
                "prompt": prompt,
            },
            indent=2,
        )
    except FileNotFoundError:
        return json.dumps(
            {"error": "No scan cache found. Run scan first."},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def verify_finding(
    finding_id: Annotated[str, Field(description="finding identifier")],
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
) -> str:
    """Verify whether a finding has been resolved after a fix."""
    try:
        findings = load_scan_cache(cache_dir)
        finding = next((f for f in findings if f.vx_id == finding_id), None)
        if finding is None:
            return json.dumps(
                {"error": f"Finding {finding_id} not found"},
                indent=2,
            )
        result = _verify_finding(finding)
        return json.dumps(
            {
                "finding_id": finding_id,
                "outcome": result.outcome.value,
                "message": result.message,
                "remaining_count": len(result.remaining_findings),
            },
            indent=2,
        )
    except FileNotFoundError:
        return json.dumps(
            {"error": "No scan cache found. Run scan first."},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def generate_report(
    format: Annotated[str, Field(description="markdown, json, or sarif")] = "markdown",
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
) -> str:
    """Generate a security report from the last scan."""
    try:
        findings = load_scan_cache(cache_dir)
        if format not in ("markdown", "json", "sarif"):
            return json.dumps(
                {"error": f"Invalid format: {format}. Use markdown, json, or sarif."},
                indent=2,
            )
        meta = {"root_dir": cache_dir, "scanners": []}
        if format == "json":
            return generate_json_report(findings, meta)
        if format == "sarif":
            from verix.reports.sarif_report import generate_sarif_report

            return generate_sarif_report(findings, meta)
        return generate_markdown_report(findings, meta)
    except FileNotFoundError:
        return json.dumps(
            {"error": "No scan cache found. Run scan first."},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def get_policy(
    config_path: Annotated[str, Field(description="path to verix.yaml")] = "verix.yaml",
) -> str:
    """Return the current Verix policy configuration as JSON."""
    try:
        config = load_policy(config_path)
        return json.dumps(config.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


@mcp.tool()
def suppress_finding_tool(
    finding_id: Annotated[str, Field(description="finding ID to suppress, e.g. VX-0001")],
    reason: Annotated[str, Field(description="why this finding is suppressed")],
    expires: Annotated[str, Field(description="expiry date YYYY-MM-DD, empty for permanent")] = "",
    added_by: Annotated[str, Field(description="who is suppressing this")] = "claude-code",
    cache_dir: Annotated[str, Field(description="cache directory")] = ".verix",
    config_path: Annotated[str, Field(description="path to verix.yaml")] = "verix.yaml",
) -> str:
    """Suppress a finding in verix.yaml with a reason."""
    try:
        findings = load_scan_cache(cache_dir)
        finding = next((f for f in findings if f.vx_id == finding_id), None)
        if finding is None:
            return json.dumps({"error": f"Finding {finding_id} not found"}, indent=2)

        config = load_policy(config_path)

        expires_date = None
        if expires:
            try:
                expires_date = datetime.strptime(expires, "%Y-%m-%d").date()
            except ValueError:
                return json.dumps(
                    {"error": "Invalid date format. Use YYYY-MM-DD"},
                    indent=2,
                )

        updated_config = add_suppression(finding, config, reason, added_by, expires_date)
        save_policy(updated_config, config_path)

        return json.dumps(
            {
                "suppressed": finding_id,
                "reason": reason,
                "expires": expires or "never",
                "suppression_id": updated_config.suppressions[-1].id,
            },
            indent=2,
        )
    except FileNotFoundError as exc:
        return json.dumps({"error": str(exc)}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


def main() -> None:
    """Run the Verix MCP server using stdio transport."""
    mcp.run()
