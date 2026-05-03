from __future__ import annotations

import json
from typing import Any

from verix import version as verix_version
from verix.findings.models import Finding, Severity


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map Verix severity to SARIF level string."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }
    return mapping.get(severity, "warning")


def _help_uri(finding: Finding) -> str | None:
    """Return a tool-specific help URI for a finding, or None."""
    if finding.scanner.tool == "semgrep":
        return f"https://semgrep.dev/r/{finding.scanner.rule_id}"
    if finding.scanner.tool == "gitleaks":
        return "https://github.com/gitleaks/gitleaks"
    return None


def _build_rules(findings: list[Finding]) -> list[dict]:
    """Build deduplicated SARIF rule objects from findings."""
    seen: set[str] = set()
    rules: list[dict] = []
    for finding in findings:
        rule_id = finding.scanner.rule_id
        if rule_id in seen:
            continue
        seen.add(rule_id)
        tags: list[str] = []
        if finding.metadata:
            cwe = finding.metadata.get("cwe")
            if isinstance(cwe, list):
                tags = cwe
            elif isinstance(cwe, str):
                tags = [cwe]
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id.split(".")[-1],
            "shortDescription": {"text": finding.message[:200]},
        }
        uri = _help_uri(finding)
        if uri:
            rule["helpUri"] = uri
        rule["properties"] = {"tags": tags}
        rules.append(rule)
    return rules


def _build_results(findings: list[Finding]) -> list[dict]:
    """Build SARIF result objects from findings."""
    results: list[dict] = []
    for finding in findings:
        line_start = finding.location.line_start or 1
        line_end = finding.location.line_end or line_start
        column_start = finding.location.column_start or 1
        column_end = finding.location.column_end or 1
        result = {
            "ruleId": finding.scanner.rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_start,
                            "endLine": line_end,
                            "startColumn": column_start,
                            "endColumn": column_end,
                        },
                    }
                }
            ],
            "fingerprints": {"verix/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity.value,
                "scanner": finding.scanner.tool,
                "status": finding.status.value,
            },
        }
        results.append(result)
    return results


def generate_sarif_report(findings: list[Finding], meta: dict) -> str:
    """Generate a SARIF 2.1.0 compliant JSON report from findings."""
    rules = _build_rules(findings)
    results = _build_results(findings)

    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Verix",
                        "version": verix_version,
                        "informationUri": "https://github.com/InsyticLabs/verix",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
