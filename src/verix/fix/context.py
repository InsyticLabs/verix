from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from verix.findings.models import Finding


class FixContext(BaseModel):
    """Immutable context for generating a security fix."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    file_path: str
    language: str
    vulnerable_lines: str
    context_before: str
    context_after: str
    rule_id: str
    message: str
    severity: str
    cwe: list[str]
    owasp: list[str]


_EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".scala": "scala",
    ".rb": "ruby",
    ".rs": "rust",
}


def _detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    return _EXTENSION_TO_LANGUAGE.get(ext, "unknown")


def extract_fix_context(finding: Finding, context_lines: int = 10) -> FixContext:
    """Read the target file and build a FixContext around the finding location."""
    file_path = finding.location.path
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    raw_lines = path.read_text().splitlines()
    total_lines = len(raw_lines)

    start_line = finding.location.line_start
    if start_line is None:
        raise ValueError("Finding location.line_start is required")
    end_line = finding.location.line_end or start_line

    context_start = max(1, start_line - context_lines)
    context_end = min(total_lines, end_line + context_lines)

    context_before = "\n".join(raw_lines[context_start - 1 : start_line - 1]).rstrip()
    vulnerable_lines = "\n".join(raw_lines[start_line - 1 : end_line]).rstrip()
    context_after = "\n".join(raw_lines[end_line:context_end]).rstrip()

    metadata = finding.metadata or {}
    cwe = metadata.get("cwe", []) if isinstance(metadata.get("cwe"), list) else []
    owasp = metadata.get("owasp", []) if isinstance(metadata.get("owasp"), list) else []

    return FixContext(
        finding_id=finding.vx_id,
        file_path=file_path,
        language=_detect_language(file_path),
        vulnerable_lines=vulnerable_lines,
        context_before=context_before,
        context_after=context_after,
        rule_id=finding.scanner.rule_id,
        message=finding.message,
        severity=finding.severity.value,
        cwe=cwe,
        owasp=owasp,
    )


def format_fix_prompt(ctx: FixContext) -> str:
    """Return a formatted fix prompt for the given fix context."""
    cwe_line = f"**CWE:** {', '.join(ctx.cwe)}" if ctx.cwe else ""
    owasp_line = f"**OWASP:** {', '.join(ctx.owasp)}" if ctx.owasp else ""

    issue_parts = [ctx.message]
    if cwe_line:
        issue_parts.append(cwe_line)
    if owasp_line:
        issue_parts.append(owasp_line)
    issue_block = "\n".join(issue_parts)

    return (
        "## Verix Fix Context\n\n"
        f"**Finding:** {ctx.finding_id}\n"
        f"**Severity:** {ctx.severity.upper()}\n"
        f"**Rule:** {ctx.rule_id}\n"
        f"**File:** {ctx.file_path}\n"
        f"**Language:** {ctx.language}\n\n"
        f"### Issue\n"
        f"{issue_block}\n\n"
        f"### Vulnerable Code\n"
        f"```{ctx.language}\n"
        f"{ctx.context_before}\n"
        f">>> {ctx.vulnerable_lines} <\n"
        f"{ctx.context_after}\n"
        f"```\n\n"
        "### Instructions\n"
        "Generate a minimal, safe fix for the vulnerable code marked with >>>.\n"
        "- Fix only the vulnerable lines\n"
        "- Do not change surrounding logic\n"
        "- Preserve existing code style\n"
        "- After showing the fix, explain what you changed and why it is safe\n"
    )
