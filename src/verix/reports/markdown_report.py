from __future__ import annotations

import datetime
from collections import Counter
from importlib.resources import files  # nosemgrep

import jinja2

from verix import version as verix_version
from verix.findings.models import Finding


def generate_markdown_report(findings: list[Finding], meta: dict) -> str:
    """Generate a Markdown report from findings using a Jinja2 template."""
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    by_severity.update(Counter(f.severity.value for f in findings))

    template_text = files("verix.reports.templates").joinpath("report.md.j2").read_text()

    env = jinja2.Environment(loader=jinja2.BaseLoader())  # nosemgrep
    template = env.from_string(template_text)

    return template.render(
        findings=[f.model_dump(mode="json") for f in findings],
        meta=meta,
        total=len(findings),
        by_severity=by_severity,
        scan_time=datetime.datetime.now(datetime.UTC).isoformat(),
        version=verix_version,
    )
