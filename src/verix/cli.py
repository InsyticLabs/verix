from __future__ import annotations

import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from verix.cache import load_scan_cache, save_scan_cache
from verix.findings.dedupe import SEVERITY_RANK
from verix.findings.models import Finding, Severity
from verix.findings.normalize import process_findings
from verix.fix.context import extract_fix_context, format_fix_prompt
from verix.fix.verify import VerifyOutcome, verify_finding
from verix.git.diff import get_changed_files
from verix.policy.init import run_policy_init
from verix.policy.loader import load_policy
from verix.policy.models import VerixConfig
from verix.policy.suppress import add_suppression, apply_suppressions
from verix.reports.json_report import generate_json_report
from verix.reports.markdown_report import generate_markdown_report
from verix.scanners.base import ScanRequest
from verix.scanners.gitleaks import GitleaksScanner
from verix.scanners.semgrep import SemgrepScanner

app = typer.Typer(
    name="verix",
    help="Local-first AppSec agent for Claude Code and the terminal.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
) -> None:
    """Initialize Verix configuration files for this project."""
    config, created = run_policy_init(Path.cwd(), force=force)

    all_files = {
        str(Path.cwd() / "verix.yaml"),
        str(Path.cwd() / ".semgrepignore"),
        str(Path.cwd() / ".gitleaksignore"),
    }

    for file_path in sorted(all_files):
        if file_path in created:
            console.print(f"[green]Created[/green] {file_path}")
        else:
            console.print(
                f"[yellow]Skipped[/yellow] {file_path} "
                "(already exists, use --force to overwrite)"
            )

    console.print(f"Initialized for {config.project.language} project.")
    console.print("Run [cyan]verix scan[/cyan] to detect issues.")


@app.command()
def scan(
    diff: bool = typer.Option(
        False, "--diff", help="Scan only changed files (staged and unstaged)"
    ),
    staged_only: bool = typer.Option(
        False, "--staged-only", help="Scan only staged changes (for pre-commit hooks)"
    ),
    severity: str = typer.Option("medium", "--severity", help="Minimum severity threshold"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON"),
    sarif: bool = typer.Option(
        False, "--sarif", help="Output SARIF format for GitHub Code Scanning"
    ),
    output: Path | None = typer.Option(None, "--output", help="Write report to file"),
) -> None:
    """Scan the codebase for vulnerabilities."""
    semgrep_scanner = SemgrepScanner()
    gitleaks_scanner = GitleaksScanner()

    available_scanners = []
    for scanner in (semgrep_scanner, gitleaks_scanner):
        if scanner.is_available():
            available_scanners.append(scanner)
        else:
            err_console.print(f"Warning: {scanner.name} is not available, skipping.")

    if not available_scanners:
        err_console.print("No scanners available. Please install semgrep or gitleaks.")
        raise typer.Exit(1)

    try:
        threshold_severity = Severity[severity.upper()]
        threshold_rank = SEVERITY_RANK[threshold_severity]
    except KeyError:
        err_console.print(f"Invalid severity: {severity}")
        raise typer.Exit(1)

    if staged_only and not diff:
        diff = True

    changed_files = []
    if diff:
        changed_files = get_changed_files(str(Path.cwd()), staged_only=staged_only)

    request = ScanRequest(
        root_dir=Path.cwd(),
        diff_only=diff,
        files=changed_files,
    )

    all_findings: list[Finding] = []
    for scanner in available_scanners:
        all_findings.extend(scanner.scan(request))

    findings = process_findings(all_findings)
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= threshold_rank]

    try:
        policy = load_policy("verix.yaml")
    except (FileNotFoundError, ValueError):
        policy = VerixConfig()

    active_findings, suppressed_findings = apply_suppressions(findings, policy)
    findings = active_findings

    save_scan_cache(findings)

    meta = {
        "root_dir": str(Path.cwd()),
        "scanners": [s.name for s in available_scanners],
    }

    if output_json:
        report_str = generate_json_report(findings, meta)
        if output:
            output.write_text(report_str, encoding="utf-8")
            err_console.print(f"Report written to {output}")
        else:
            typer.echo(report_str)
    elif sarif:
        from verix.reports.sarif_report import generate_sarif_report

        report_str = generate_sarif_report(findings, meta)
        if output:
            output.write_text(report_str)
            err_console.print(f"Report written to {output}")
        else:
            console.print(report_str)
    else:
        if not findings:
            console.print("[green]No findings. Your code looks clean.[/green]")
        else:
            table = Table(show_header=True, header_style="bold")
            table.add_column("ID")
            table.add_column("Severity")
            table.add_column("Message")
            table.add_column("File")
            table.add_column("Line")

            for finding in findings:
                line = (
                    str(finding.location.line_start)
                    if finding.location.line_start is not None
                    else ""
                )
                table.add_row(
                    finding.vx_id,
                    Text(
                        finding.severity.value,
                        style=_severity_style(finding.severity),
                    ),
                    finding.message,
                    finding.location.path,
                    line,
                )

            console.print(table)

            counts = Counter(f.severity.value for f in findings)
            summary = (
                f"Found {len(findings)} findings: "
                f"{counts.get('critical', 0)} critical, "
                f"{counts.get('high', 0)} high, "
                f"{counts.get('medium', 0)} medium, "
                f"{counts.get('low', 0)} low, "
                f"{counts.get('info', 0)} info"
            )
            console.print(summary)

            if suppressed_findings:
                console.print(
                    f"[dim]{len(suppressed_findings)} finding(s) suppressed by policy.[/dim]"
                )

        if output:
            report_str = generate_markdown_report(findings, meta)
            output.write_text(report_str)
            err_console.print(f"Report written to {output}")

        if findings:
            raise typer.Exit(1)


@app.command()
def explain(
    finding_id: str = typer.Argument(..., help="Finding ID to explain, e.g. VX-0001"),
) -> None:
    """Explain a finding from the last scan."""
    try:
        findings = load_scan_cache()
    except FileNotFoundError:
        err_console.print("No scan cache found. Run `verix scan` first.")
        raise typer.Exit(1)

    finding = None
    for f in findings:
        if f.vx_id == finding_id:
            finding = f
            break

    if finding is None:
        err_console.print(f"Finding {finding_id} not found.")
        raise typer.Exit(1)

    lines: list[str] = []
    lines.append(f"Severity: {finding.severity.value}")
    lines.append(f"File: {finding.location.path}")
    if finding.location.line_start is not None:
        lines.append(f"Line: {finding.location.line_start}")
    lines.append(f"Scanner: {finding.scanner.tool} — {finding.scanner.rule_id}")
    if finding.metadata:
        cwe = finding.metadata.get("cwe")
        if cwe:
            if isinstance(cwe, list):
                lines.append(f"CWE: {', '.join(cwe)}")
            else:
                lines.append(f"CWE: {cwe}")
        owasp = finding.metadata.get("owasp")
        if owasp:
            if isinstance(owasp, list):
                lines.append(f"OWASP: {', '.join(owasp)}")
            else:
                lines.append(f"OWASP: {owasp}")
    if finding.evidence:
        lines.append("Evidence:")
        lines.append(f"```\n{finding.evidence}\n```")
    recommendation = getattr(finding, "recommendation", None)
    if recommendation:
        lines.append(f"Recommendation: {recommendation}")

    content = Text("\n".join(lines))
    panel = Panel(content, title=f"{finding.vx_id}: {finding.message}")
    console.print(panel)


@app.command()
def report(
    format: str = typer.Option("markdown", "--format", help="Output format: markdown or json"),
    output: Path | None = typer.Option(None, "--output", help="Write to file"),
) -> None:
    """Generate a report from the last scan."""
    try:
        findings = load_scan_cache()
    except FileNotFoundError:
        err_console.print("No scan cache found. Run `verix scan` first.")
        raise typer.Exit(1)

    meta = {"root_dir": str(Path.cwd())}

    if format == "json":
        report_str = generate_json_report(findings, meta)
        if output:
            output.write_text(report_str, encoding="utf-8")
            err_console.print(f"Report written to {output}")
        else:
            typer.echo(report_str)
    elif format == "markdown":
        report_str = generate_markdown_report(findings, meta)
        if output:
            output.write_text(report_str)
            err_console.print(f"Report written to {output}")
        else:
            console.print(report_str)
    else:
        err_console.print(f"Invalid format: {format}. Use 'markdown' or 'json'.")
        raise typer.Exit(1)


@app.command()
def fix(
    finding_id: str = typer.Argument(..., help="Finding ID, e.g. VX-0001"),
    context_lines: int = typer.Option(10, "--context", help="Lines of context"),
) -> None:
    """Show fix context for a finding so Claude Code can generate a patch."""
    try:
        findings = load_scan_cache()
    except FileNotFoundError:
        err_console.print("No scan cache found. Run `verix scan` first.")
        raise typer.Exit(1)

    finding = None
    for f in findings:
        if f.vx_id == finding_id:
            finding = f
            break

    if finding is None:
        err_console.print(f"Finding {finding_id} not found.")
        raise typer.Exit(1)

    try:
        ctx = extract_fix_context(finding, context_lines)
    except FileNotFoundError:
        err_console.print(f"File not found: {finding.location.path}")
        raise typer.Exit(1)

    prompt = format_fix_prompt(ctx)
    console.print(prompt)
    console.print(
        "\n[bold]Next step:[/bold] Review the context above. "
        f"After applying the fix, run: [cyan]verix verify {finding_id}[/cyan]"
    )


@app.command()
def verify(
    finding_id: str = typer.Argument(..., help="Finding ID, e.g. VX-0001"),
) -> None:
    """Verify whether a finding has been resolved."""
    try:
        findings = load_scan_cache()
    except FileNotFoundError:
        err_console.print("No scan cache found. Run `verix scan` first.")
        raise typer.Exit(1)

    finding = None
    for f in findings:
        if f.vx_id == finding_id:
            finding = f
            break

    if finding is None:
        err_console.print(f"Finding {finding_id} not found.")
        raise typer.Exit(1)

    result = verify_finding(finding)

    if result.outcome == VerifyOutcome.FIXED:
        border = "green"
        title = "Fixed"
    elif result.outcome == VerifyOutcome.STILL_PRESENT:
        border = "red"
        title = "Still Present"
    else:
        border = "yellow"
        title = "Inconclusive"

    panel = Panel(result.message, title=title, border_style=border)
    console.print(panel)


def _severity_style(severity: Severity) -> str:
    """Return the Rich style string for a severity level."""
    mapping = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return mapping.get(severity, "")


policy_app = typer.Typer(help="Manage Verix security policy.")
app.add_typer(policy_app, name="policy")


@policy_app.command("init")
def policy_init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing files"),
) -> None:
    """Generate verix.yaml, .semgrepignore, and .gitleaksignore."""
    config, created = run_policy_init(Path.cwd(), force=force)

    all_files = {
        str(Path.cwd() / "verix.yaml"),
        str(Path.cwd() / ".semgrepignore"),
        str(Path.cwd() / ".gitleaksignore"),
    }

    for file_path in sorted(all_files):
        if file_path in created:
            console.print(f"[green]Created[/green] {file_path}")
        else:
            console.print(
                f"[yellow]Skipped[/yellow] {file_path} (already exists, use --force to overwrite)"
            )

    console.print(f"Policy initialized for {config.project.language} project")
    console.print("Run [cyan]verix scan[/cyan] to detect issues")


@policy_app.command("validate")
def policy_validate() -> None:
    """Validate the current verix.yaml configuration."""
    try:
        config = load_policy("verix.yaml")
    except FileNotFoundError:
        err_console.print("No verix.yaml found. Run verix policy init first.")
        raise typer.Exit(1)
    except ValueError as exc:
        err_console.print(f"Invalid verix.yaml: {exc}")
        raise typer.Exit(1)

    console.print("[green]verix.yaml is valid.[/green]")
    console.print(f"Project: {config.project.name} ({config.project.language})")
    console.print(f"Suppressions: {len(config.suppressions)} active")
    console.print(f"Severity threshold: {config.scan.severity_threshold}")


@policy_app.command("suppress")
def policy_suppress(
    finding_id: str = typer.Argument(..., help="Finding ID to suppress, e.g. VX-0001"),
    reason: str = typer.Option(..., "--reason", "-r", help="Why this finding is suppressed"),
    expires: str | None = typer.Option(None, "--expires", help="Expiry date YYYY-MM-DD"),
    added_by: str = typer.Option("unknown", "--by", help="Who is suppressing this"),
) -> None:
    """Suppress a finding in verix.yaml with a reason."""
    try:
        findings = load_scan_cache()
    except FileNotFoundError:
        err_console.print("No scan cache found. Run `verix scan` first.")
        raise typer.Exit(1)

    finding = None
    for f in findings:
        if f.vx_id == finding_id:
            finding = f
            break

    if finding is None:
        err_console.print(f"Finding {finding_id} not found.")
        raise typer.Exit(1)

    try:
        config = load_policy("verix.yaml")
    except FileNotFoundError:
        err_console.print("No verix.yaml found. Run verix policy init first.")
        raise typer.Exit(1)

    expiry_date = None
    if expires:
        try:
            expiry_date = datetime.strptime(expires, "%Y-%m-%d").date()
        except ValueError:
            err_console.print("Invalid date format. Use YYYY-MM-DD")
            raise typer.Exit(1)

    updated = add_suppression(finding, config, reason, added_by, expiry_date)

    from verix.policy.loader import save_policy

    save_policy(updated, "verix.yaml")

    console.print(f"[green]Suppressed[/green] {finding_id}")
    console.print(f"Reason: {reason}")
    if expires:
        console.print(f"Expires: {expires}")
    console.print("Run [cyan]verix scan[/cyan] to confirm the finding is suppressed")


@policy_app.command("suppressions")
def policy_suppressions() -> None:
    """List all suppressions in verix.yaml."""
    try:
        config = load_policy("verix.yaml")
    except FileNotFoundError:
        err_console.print("No verix.yaml found. Run verix policy init first.")
        raise typer.Exit(1)

    if not config.suppressions:
        console.print("No suppressions configured.")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Reason")
    table.add_column("Expires")
    table.add_column("Active")

    today = datetime.now().date()

    for s in config.suppressions:
        if s.expires and s.expires < today:
            style = "red"
        elif s.expires and (s.expires - today).days <= 30:
            style = "yellow"
        elif s.active:
            style = "green"
        else:
            style = "dim"

        expires_str = str(s.expires) if s.expires else "Never"
        active_str = "Yes" if s.active else "No"

        table.add_row(
            s.id,
            s.rule_id,
            s.file,
            s.reason,
            expires_str,
            Text(active_str, style=style),
        )

    console.print(table)


@policy_app.command("diff")
def policy_diff() -> None:
    """Show what changed in verix.yaml since the last git commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD", "--", "verix.yaml"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            err_console.print("Could not run git diff. Is this a git repository?")
            raise typer.Exit(1)
    except Exception:
        err_console.print("Could not run git diff. Is this a git repository?")
        raise typer.Exit(1)

    diff_output = result.stdout
    if not diff_output.strip():
        console.print("No changes to verix.yaml since last commit.")
        return

    syntax = Syntax(diff_output, "diff", theme="monokai")
    console.print(syntax)


ci_app = typer.Typer(help="CI/CD integration for Verix.")
app.add_typer(ci_app, name="ci")


@ci_app.command("init")
def ci_init(
    ci: str = typer.Option("github", "--ci", help="CI system: github"),
    block_on: str = typer.Option(
        "high", "--block-on", help="Severity to block on: critical, high, medium"
    ),
    no_sarif: bool = typer.Option(False, "--no-sarif", help="Disable SARIF upload step"),
    python_version: str = typer.Option("3.12", "--python-version", help="Python version to use"),
) -> None:
    """Generate CI workflow file for Verix security scanning."""
    if ci != "github":
        err_console.print(f"Unsupported CI system: {ci}. Currently only 'github' is supported.")
        raise typer.Exit(1)

    try:
        Severity[block_on.upper()]
    except KeyError:
        err_console.print(f"Invalid severity: {block_on}")
        raise typer.Exit(1)

    workflow_path = Path.cwd() / ".github" / "workflows" / "verix.yml"
    if workflow_path.exists():
        err_console.print(f"Warning: {workflow_path} already exists and will be overwritten.")

    from verix.ci.github import write_github_workflow

    write_github_workflow(
        output_dir=Path.cwd(),
        block_on_severity=block_on,
        sarif_upload=not no_sarif,
        python_version=python_version,
    )

    console.print("[green]Created[/green] .github/workflows/verix.yml")
    console.print(f"Blocks on: {block_on} severity and above")
    if not no_sarif:
        console.print("SARIF upload: enabled (requires GitHub Advanced Security)")
    console.print("\nCommit and push to activate the workflow.")


hooks_app = typer.Typer(help="Manage Verix git hooks.")
app.add_typer(hooks_app, name="hooks")


@hooks_app.command("install")
def hooks_install(
    force: bool = typer.Option(False, "--force", help="Overwrite existing hook"),
) -> None:
    """Install Verix pre-commit git hook."""
    from verix.hooks.git import install_pre_commit_hook

    try:
        install_pre_commit_hook(Path.cwd(), force=force)
    except ValueError as exc:
        err_console.print(str(exc))
        raise typer.Exit(1)
    except FileExistsError as exc:
        err_console.print(str(exc))
        raise typer.Exit(1)

    console.print("[green]Installed[/green] pre-commit hook")
    console.print("Verix will scan staged changes before each commit.")
    console.print("Blocks on: high severity findings")
    console.print("To skip: git commit --no-verify")


@hooks_app.command("uninstall")
def hooks_uninstall() -> None:
    """Remove Verix pre-commit git hook."""
    from verix.hooks.git import uninstall_pre_commit_hook

    try:
        uninstall_pre_commit_hook(Path.cwd())
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(str(exc))
        raise typer.Exit(1)

    console.print("[green]Removed[/green] pre-commit hook")


@hooks_app.command("status")
def hooks_status_cmd() -> None:
    """Show status of Verix git hooks."""
    from verix.hooks.git import hook_status

    status = hook_status(Path.cwd())
    if not status["is_git_repo"]:
        err_console.print("Not a git repository.")
        raise typer.Exit(1)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Hook")
    table.add_column("Status")

    if status["pre_commit_installed"]:
        table.add_row("pre-commit", Text("installed", style="green"))
    else:
        table.add_row("pre-commit", Text("not installed", style="yellow"))

    console.print(table)
    console.print(f"Hooks directory: {status['hooks_dir']}")


if __name__ == "__main__":
    app()
