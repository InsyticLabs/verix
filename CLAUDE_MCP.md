# Verix MCP Setup

## Requirements

Verix must be installed as a uv tool before registering the MCP server:

```bash
uv tool install verix
```

## Register with Claude Code

Run this command once:

```bash
claude mcp add verix -- verix-mcp
```

That is all. No path configuration needed when installed via uv tool.

## Verify registration

```bash
claude mcp list
```

You should see verix in the list.

## Development setup (running from source)

If you are working on Verix itself rather than using it as a tool:

```bash
# Clone the repo
git clone https://github.com/InsyticLabs/verix
cd verix

# Install dependencies
uv sync

# Register MCP from source
claude mcp add verix -- uv run --directory ~/workspace/verix verix-mcp
```

> pip and pipx are not supported install paths.
> Use uv tool install verix.

## Available MCP tools

| Tool | What it does |
|------|-------------|
| scan_repo | Full repository scan |
| scan_file | Single file scan |
| scan_diff | Scan git diff only |
| get_findings | Retrieve last scan results |
| explain_finding | Get finding details |
| fix_context | Get fix context for Claude Code |
| verify_finding | Check if finding is resolved |
| generate_report | Generate markdown or JSON report |

## Usage in Claude Code

Once registered, Claude Code can call Verix tools directly:

"Scan this repo for security issues"
-> Claude Code calls scan_repo automatically

"Explain VX-0001"
-> Claude Code calls explain_finding("VX-0001")

"Is VX-0001 fixed?"
-> Claude Code calls verify_finding("VX-0001")

## Troubleshooting

If tools are not appearing:
  claude mcp remove verix
  claude mcp add verix -- verix-mcp

If scanner not found errors appear:
  uv tool install semgrep
  brew install gitleaks
