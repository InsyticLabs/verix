# Contributing to Verix

Thank you for considering a contribution. This document covers how to set up the project locally, the conventions we follow, and how to open a pull request.

## Development Setup

You need [uv](https://docs.astral.sh/uv/) installed. The project uses `uv` for dependency management, running tests, and linting.

```bash
# Clone the repo
git clone https://github.com/InsyticLabs/verix
cd verix

# Install dependencies
uv sync

# Run tests
make test

# Run the full check suite
make all
```

The Makefile provides these common targets:

| Target | Command |
|--------|---------|
| `make install` | `uv sync` |
| `make test` | `uv run pytest` |
| `make lint` | `uv run ruff check src tests` |
| `make format` | `uv run ruff format src tests` |
| `make typecheck` | `uv run pyright src` |
| `make all` | lint, typecheck, test |

## Adding a Scanner Adapter

Scanner adapters bridge Verix to external security tools (e.g., Semgrep, Gitleaks). For a full guide on how to write and register a new adapter, see [AGENTS.md](AGENTS.md).

In short:

1. Create `src/verix/scanners/<name>.py` extending `ScannerAdapter`
2. Set `name = "<name>"` on the class
3. Implement `is_available()` and `scan()` returning `list[Finding]`
4. Add tests in `tests/scanners/test_<name>.py`

The adapter auto-registers via `__init_subclass__`.

## Adding a Security Profile

Verix uses `verix.yaml` for per-project configuration and the policy engine for suppressions and severity overrides. There is no separate `profiles/` directory in the current codebase. To add behavior tied to a specific project type or scanner set, extend the policy engine in `src/verix/policy/` and add matching tests in `tests/policy/`.

## Commit Message Format

We use ticket-prefixed commit messages:

```
VX-0001: Add scanner adapter base class
VX-0002-A: Implement Semgrep adapter
VX-0002-B: Add Semgrep adapter tests
SmokeTest: Add vulnerable-app smoke test
```

Format:

- Prefix with the ticket ID (e.g., `VX-0001`)
- For multi-part work, append `-A`, `-B`, etc. (e.g., `VX-0001-A`)
- Use the imperative mood: "Add", "Fix", "Update", not "Added" or "Fixes"
- Keep the subject line under 72 characters when possible

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes and add tests
3. Run `make all` locally and ensure everything passes
4. Open a pull request against `main`
5. Fill out the PR description with what changed and why
6. Ensure CI passes before requesting review

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful, constructive, and inclusive in all interactions.

## Reporting Security Issues

Please do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the private reporting process.
