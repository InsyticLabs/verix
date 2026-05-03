# Verix

[![PyPI](https://img.shields.io/pypi/v/verix)](https://pypi.org/project/verix/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/InsyticLabs/verix/actions/workflows/ci.yml/badge.svg)](https://github.com/InsyticLabs/verix/actions)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)

Local-first AppSec agent for Claude Code and the terminal.

## What it does

- **Scan** — Detects security vulnerabilities and leaked secrets in your codebase using Semgrep and Gitleaks
- **Explain** — Describes findings in plain English with exploit scenarios and fix guidance
- **Fix** — Generates minimal, safe patches for findings
- **Verify** — Re-scans after fixes to confirm vulnerabilities are resolved

## Why Verix

AI coding tools ship code faster than ever, including insecure code. Existing security scanners find issues but stop there — they do not understand your project context, explain findings in plain terms, or help you fix them.

Verix closes the loop. It runs entirely on your machine, reads your code, and gives you actionable security feedback without sending anything to the cloud.

## Requirements

- [uv](https://docs.astral.sh/uv/) — Verix uses uv for installation and execution
- [Semgrep](https://semgrep.dev/) — for SAST scanning
- [Gitleaks](https://github.com/gitleaks/gitleaks) — for secret detection

Install uv if you do not have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install Semgrep and Gitleaks:

```bash
uv tool install semgrep
brew install gitleaks   # macOS
# or: https://github.com/gitleaks/gitleaks#installing
```

## Installation

```bash
uv tool install verix
```

## Quick Start

```bash
# Initialize Verix in your project
verix init

# Run your first scan
verix scan

# Explain a finding
verix explain VX-0001

# Generate a report
verix report
```

**Example output:**

```
$ verix scan
Verix v0.1.0
Scanning: /home/dev/my-project

VX-0001 [HIGH]   Avoiding SQL string concatenation: untrusted input concatenated
                 with raw SQL query can result in SQL Injection. In order to
                 execute raw query safely, prepared statement should be used.
                 app.py:12
VX-0002 [MEDIUM] Detected possible formatted SQL query. Use parameterized
                 queries instead.
                 app.py:12
VX-0003 [MEDIUM] Detected the use of eval(). eval() can be dangerous if used
                 to evaluate dynamic content. If this content can be input from
                 outside the program, this may be a code injection vulnerability.
                 app.py:17

Found 3 findings: 0 critical, 1 high, 2 medium, 0 low, 0 info
Run `verix explain VX-0001` for details.
```

## Configuration

Run `verix policy init` to generate verix.yaml for your project.
The file is gitignored and should not be committed.

## Commands (v0.1)

| Command | Description |
|---------|-------------|
| `verix init` | Create `verix.yaml` config in the current directory |
| `verix scan` | Scan the codebase for vulnerabilities and secrets |
| `verix scan --diff` | Scan only changed files (useful in CI/pre-commit) |
| `verix scan --severity high` | Filter findings by minimum severity |
| `verix scan --json` | Output findings as JSON instead of terminal UI |
| `verix explain VX-0001` | Explain a specific finding in plain English |
| `verix fix VX-0001` | Show fix context for a finding |
| `verix verify VX-0001` | Verify whether a finding has been resolved |
| `verix report` | Generate a markdown or JSON report |

## Claude Code Integration

Verix provides slash commands inside Claude Code so you can scan, explain, and fix security issues without leaving your editor.

| Slash Command | Purpose |
|---------------|---------|
| `/verix-scan` | Scan and summarize findings |
| `/verix-scan-diff` | Scan diff-only and flag new issues |
| `/verix-explain VX-0001` | Explain a specific finding |
| `/verix-fix VX-0001` | Propose and apply a fix |
| `/verix-report` | Generate and export a report |

> Verix must be installed via `uv tool install verix` before
> Claude Code slash commands will work. The MCP server also requires
> this installation path.

## Roadmap

| Version | Theme | Status |
|---------|-------|--------|
| 0.1.0 | Local scanner + Claude Code integration + Fix loop + MCP server + Policy engine + CI + Hooks | Released |
| 0.2.0 | GitLab CI support, post-edit Claude Code hook, dependency change hook | Planned |
| 0.3.0 | Business logic security rules, threat model generation | Planned |
| 0.4.0 | Web dashboard, team features | Planned |

## What Verix is not

- A replacement for a skilled security engineer
- Runtime protection or a WAF
- A compliance or audit tool
- A cloud-based service — all processing happens locally
- A tool that sends your code to external APIs (in v0.1)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

To report security vulnerabilities, see [SECURITY.md](SECURITY.md).

## About

Verix is built by [Insytic Labs](https://github.com/InsyticLabs).

## License

[Apache 2.0](LICENSE)
