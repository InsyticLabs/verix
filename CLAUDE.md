# Verix

A local-first, open-source AppSec agent for Claude Code and the terminal. Scans code for security vulnerabilities, explains findings, suggests patches, and verifies fixes. All processing stays local. No external services in v0.1.

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│  CLI Layer (typer + rich)                     │
│  init, scan, explain, report commands         │
└─────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────┐
│  Scanner Adapter Layer                      │
│  ┌─────────────┐  ┌─────────────┐          │
│  │ Semgrep     │  │ Gitleaks    │          │
│  │ Adapter     │  │ Adapter     │          │
│  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────┐
│  Finding Normalization Layer                │
│  - deduplicate by fingerprint               │
│  - sort by severity                         │
│  - assign VX-IDs                            │
└─────────────────────────────────────────────┘
                      │
┌──────────┐  ┌──────────────┐  ┌─────────────┐
│ Report   │  │ Explain      │  │ Cache       │
│ Layer    │  │ Layer        │  │ Layer       │
│ markdown │  │ display only │  │ .verix/│
│ json     │  │ LLM in v0.3  │  │ last_scan.  │
│          │  │              │  │ json        │
└──────────┘  └──────────────┘  └─────────────┘
                      │
┌─────────────────────────────────────────────┐
│  Config Layer (verix.yaml)             │
│  scanners, paths, ignores, severity filter  │
└─────────────────────────────────────────────┘
```

## Module Map

src/verix/
  cli.py              -- all CLI commands (typer)
  cache.py            -- last_scan.json read/write
  findings/           -- Finding model, normalize, dedupe, fingerprint
  scanners/           -- Semgrep and Gitleaks adapters
  reports/            -- JSON, Markdown, SARIF report generators
  fix/                -- fix context extraction and verification
  policy/             -- verix.yaml model, loader, suppress
  mcp/                -- FastMCP server with 10 tools
  ci/                 -- GitHub Actions workflow generator
  hooks/              -- git pre-commit hook installer
  git/                -- git diff file discovery

## Directory Structure

```
src/verix/
├── __init__.py           # Package version
├── cli.py                # Typer commands and entry point
├── cache.py              # Read/write .verix/last_scan.json
├── ci/
│   ├── __init__.py
│   └── github.py         # GitHub Actions workflow generator
├── config/
│   ├── __init__.py
│   ├── loader.py         # Config loader (placeholder)
│   └── models.py         # Pydantic models for verix.yaml
├── explain/
│   ├── __init__.py
│   └── explain.py        # Finding explanation (placeholder)
├── findings/
│   ├── __init__.py
│   ├── models.py         # Finding, Severity, Location Pydantic models
│   ├── normalize.py      # Severity sorting and finding normalization
│   ├── dedupe.py         # Deduplicate findings by fingerprint
│   └── fingerprint.py    # Generate stable fingerprints for findings
├── fix/
│   ├── __init__.py
│   ├── context.py        # Fix context extraction and prompt formatting
│   └── verify.py         # Fix verification by re-scanning
├── git/
│   ├── __init__.py
│   └── diff.py           # Changed file discovery via git diff
├── hooks/
│   ├── __init__.py
│   └── git.py            # Pre-commit hook installer
├── mcp/
│   ├── __init__.py
│   └── server.py         # FastMCP server with tools
├── policy/
│   ├── __init__.py
│   ├── init.py           # Project detection and initial policy generation
│   ├── loader.py         # YAML policy load/save
│   ├── models.py         # Pydantic policy models for verix.yaml
│   └── suppress.py       # Suppression helpers
├── reports/
│   ├── __init__.py
│   ├── json_report.py    # JSON report generator
│   ├── markdown_report.py# Markdown report generator
│   ├── sarif_report.py   # SARIF report generator
│   └── templates/
│       ├── __init__.py
│       └── report.md.j2  # Jinja2 template for markdown reports
├── scanners/
│   ├── __init__.py
│   ├── base.py           # ScannerAdapter base class and registry
│   ├── semgrep.py        # Semgrep adapter: subprocess, parse JSON output
│   └── gitleaks.py       # Gitleaks adapter: subprocess, parse JSON output, redact secrets

tests/
├── conftest.py           # Shared fixtures
├── test_cli.py           # CLI command tests
├── test_cache.py         # Cache read/write tests
├── ci/
│   ├── __init__.py
│   └── test_github.py    # GitHub workflow generator tests
├── findings/
│   ├── __init__.py
│   ├── test_models.py    # Finding and severity model tests
│   ├── test_normalize.py # Normalization and sorting tests
│   ├── test_dedupe.py    # Deduplication logic tests
│   └── test_fingerprint.py # Fingerprint stability tests
├── fix/
│   ├── __init__.py
│   ├── test_context.py   # Fix context extraction tests
│   └── test_verify.py    # Verify workflow tests
├── git/
│   ├── __init__.py
│   └── test_diff.py      # Git diff utility tests
├── hooks/
│   ├── __init__.py
│   └── test_git.py       # Git hook install/uninstall tests
├── mcp/
│   ├── __init__.py
│   ├── test_server.py    # MCP server registration tests
│   ├── test_scan_tools.py # MCP scan tool tests
│   ├── test_fix_tools.py  # MCP fix tool tests
│   └── test_policy_tools.py # MCP policy tool tests
├── policy/
│   ├── __init__.py
│   ├── test_init.py      # Policy init tests
│   ├── test_loader.py    # Policy loader tests
│   ├── test_models.py    # Policy model tests
│   ├── test_suppress.py  # Suppression tests
│   └── test_diff.py      # Policy diff command tests
├── reports/
│   ├── __init__.py
│   ├── test_json_report.py   # JSON output tests
│   ├── test_markdown_report.py # Markdown output tests
│   └── test_sarif_report.py # SARIF output tests
├── scanners/
│   ├── __init__.py
│   ├── test_base.py      # Scanner registry tests
│   ├── test_semgrep.py   # Mocked Semgrep adapter tests
│   └── test_gitleaks.py  # Mocked Gitleaks adapter + redaction tests
└── smoke/
    ├── __init__.py
    └── test_vulnerable_app.py # End-to-end CLI and scanner integration tests
```

## Coding Rules

These rules are strict and apply to every edit.

- **No print() outside cli.py.** Use `logging` or return values. cli.py is the only place that prints to stdout.
- **No hardcoded paths.** Always derive paths from `ScanRequest.root_dir` or `config`.
- **Never mutate a Finding in place.** Always return a new `Finding` object.
- **Never store raw secret values.** Redact before storing; evidence field stores first 4 chars + `****`.
- **Always use Pydantic v2 syntax.** Use `model_config = ConfigDict(...)`; never `class Config`.
- **Always use `StrEnum`** from `enum` (stdlib, Python 3.11+); do not use `Enum` with string mixins.
- **Always use `from __future__ import annotations`** at the top of every file.
- **Every public function must have a one-line docstring.**
- **No wildcard imports anywhere.**
- **All subprocess calls must have a timeout.** Default is 120 seconds.
- **All subprocess calls must capture both stdout and stderr.**

## Testing Rules

- Every scanner adapter must have unit tests with mocked subprocess calls.
- Unit tests must not make real subprocess calls; mock `subprocess.run`.
- Smoke/integration tests (for example, under `tests/smoke/`) may invoke real subprocesses such as the CLI or Semgrep when validating end-to-end behavior.
- Every Pydantic model must have at least one round-trip serialization test.
- Tests live in `tests/` and mirror the `src/verix/` structure.
- Run all tests: `uv run pytest`
- Run single test: `uv run pytest tests/scanners/test_semgrep.py -v`

## Finding ID Format

- v0.1: `VX-0001`, `VX-0002` -- sequential, 4 digits, zero-padded
- Future: `VX-SAST-0001`, `VX-SECRET-0001`, `VX-DEPS-0001`, `VX-POLICY-0001`

## Severity Levels

- `critical`, `high`, `medium`, `low`, `info`
- Secrets from Gitleaks are always `high`
- Semgrep mapping: `ERROR` -> `high`, `WARNING` -> `medium`, `INFO` -> `info`

## Version Roadmap

| Version | Milestone | Status |
|---------|-----------|--------|
| v0.1 | scan, explain, report (CLI only) | Done |
| v0.2 | Claude Code slash commands | Done |
| v0.3 | fix, verify (patch generation) | Done |
| v0.4 | MCP server | Done |
| v0.5 | policy engine | Done |
| v1.0 | full AppSec agent | Done |

## What NOT to Build Yet

Do not implement these without a new design session:
- Threat model generation (requires LLM -- v1.1)
- GitLab CI support (v1.1)
- Bitbucket CI support (v1.1)
- Post-edit Claude Code hook (v1.1)
- Dependency change hook (v1.1)
- Business logic security rules (v1.1)
- Web dashboard (future)
- Team/enterprise features (future)

## Common Commands

**Makefile:**

- `make install` -- `uv sync`
- `make test` -- `uv run pytest`
- `make lint` -- `uv run ruff check src tests`
- `make format` -- `uv run ruff format src tests`
- `make typecheck` -- `uv run pyright src`
- `make all` -- lint, typecheck, test

**CLI:**

- `verix init`
- `verix scan`
- `verix scan --diff`
- `verix scan --severity high`
- `verix scan --json`
- `verix explain VX-0001`
- `verix report`
- `verix report --format json --output report.json`
- `verix scan --sarif`
- `verix scan --sarif --output verix.sarif`
- `verix ci init`
- `verix ci init --block-on critical --no-sarif`
- `verix hooks install`
- `verix hooks uninstall`
- `verix hooks status`
- `verix policy init`
- `verix policy validate`
- `verix policy suppress VX-0001 --reason "false positive" --by developer`
- `verix policy suppressions`
- `verix policy diff`

## Security Rules

- Raw secret values must **never** be stored anywhere.
- The `evidence` field stores only the first 4 characters + `****` of any detected secret.
- Raw scanner dicts must replace secret values with `[REDACTED]` before storage.
- Verix must **never** send code to any external service in v0.1.
- All processing is local.

Examples:

- `feat(scanner): add semgrep adapter`
- `fix(findings): correct severity mapping for semgrep ERROR level`
- `test(scanner): add gitleaks secret redaction test`
- `docs(readme): add installation instructions`
