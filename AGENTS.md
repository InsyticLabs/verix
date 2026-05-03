# Verix Agent Guide

## What Verix is

Verix is a local-first, open-source AppSec agent for Claude Code and the terminal. It scans code for security vulnerabilities, explains findings, suggests patches, and verifies fixes. All processing stays local. No external services in v0.1. Built in Python with uv, Typer, and Rich.

## How to run Verix

All commands must be run via uv:

```bash
uv run verix <command>
```

Or if installed as a tool:

```bash
verix <command>
```

Never use pip. For normal/end-user usage, do not use `python -m verix`; prefer `uv run verix <command>` or `verix <command>`. In development and tests, `python -m verix.cli` may be used when invoking the CLI module directly is necessary.

## Available commands (v0.1)

| Command | What it does | When to use it |
|---------|-------------|----------------|
| `init` | Detect project type and create `verix.yaml` | First time setup |
| `scan` | Run all configured scanners and store findings | Regular security check |
| `scan --diff` | Scan only files changed in the current git diff | Pre-commit review |
| `explain <id>` | Show details for a specific finding | Deep-dive into a finding |
| `report` | Generate markdown or JSON report from last scan | Share results |

## Slash commands available

| Slash command | Purpose |
|---------------|---------|
| `/verix-init` | Initialize Verix for the project |
| `/verix-scan` | Run a full scan and summarize findings |
| `/verix-scan-diff` | Scan only changed files before committing |
| `/verix-explain` | Explain a specific finding in plain English |
| `/verix-fix` | Describe or apply a fix for a finding |
| `/verix-report` | Generate and export a report |

## What agents should NOT do

- Do not run `verix fix --apply` without explicit user confirmation
- Do not commit after applying fixes
- Do not push to remote
- Do not install dependencies with pip
- Do not modify `src/verix/findings/models.py` without explicit instruction (it is the core contract)
- Do not add LLM calls anywhere -- that is v0.3+
- Do not add MCP server code -- that is v0.4+

## How to run tests

```bash
uv run pytest
uv run pytest tests/scanners/ -v
uv run pytest tests/smoke/ -v -s
```

## How to add a new scanner adapter

Three steps:

1. Create `src/verix/scanners/<name>.py` extending `ScannerAdapter`
2. Set class-level `name = "<name>"`
3. Implement `is_available()` and `scan()` returning `list[Finding]`

The adapter auto-registers via `__init_subclass__`.

Create matching tests in `tests/scanners/test_<name>.py`.

## Finding model contract

Finding is frozen (immutable). Never mutate.

Always use `model_copy(update={...})` to create modified copies.

`vx_id` format: `VX-0001` (assigned by `normalize_findings`, not by adapters).

Adapters always use `vx_id="VX-0000"` as placeholder.

Secret values must always be redacted before storing in `evidence` or `raw_finding`.

## Cache

Last scan stored in `.verix/last_scan.json`

`explain` and `report` commands read from this cache.

Cache is gitignored.
