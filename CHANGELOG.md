# Changelog

All notable changes to Verix are documented here.

## [0.1.0] - 2026-05-02

### Added
- Semgrep SAST scanner adapter
- Gitleaks secret detection adapter
- Finding normalization, deduplication, fingerprinting
- JSON and Markdown report generation
- Scan cache (.verix/last_scan.json)
- CLI: init, scan, explain, report commands
- Git diff support (verix scan --diff)
- Claude Code slash commands (.claude/commands/)
- AGENTS.md for Claude Code agent guidance
- Fix context extraction (verix fix)
- Finding verification after fix (verix verify)
- FixContext and VerifyResult models
- Language detection from file extension
- FastMCP server with 10 tools for Claude Code agent use
- verix-mcp entry point
- Policy engine with verix.yaml support
- Finding suppression with expiry (verix policy suppress)
- Project-aware .semgrepignore and .gitleaksignore generation
- Policy-aware scanning (suppressed findings filtered automatically)
- verix policy init, validate, diff, suppressions commands
- Git pre-commit hook installer (verix hooks install/uninstall/status)
- SARIF 2.1.0 output for GitHub Code Scanning (verix scan --sarif)
- GitHub Actions workflow generator (verix ci init)
