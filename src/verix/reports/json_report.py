from __future__ import annotations

import datetime
import json
from collections import Counter

from verix import version as verix_version
from verix.findings.models import Finding


def generate_json_report(findings: list[Finding], meta: dict) -> str:
    """Generate a pretty-printed JSON report from findings."""
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    by_severity.update(Counter(f.severity.value for f in findings))

    report = {
        "verix_version": verix_version,
        "scan_time": datetime.datetime.now(datetime.UTC).isoformat(),
        "total": len(findings),
        "by_severity": by_severity,
        "meta": meta,
        "findings": [f.model_dump(mode="json") for f in findings],
    }

    return json.dumps(report, indent=2)
