from __future__ import annotations

import asyncio

from verix.mcp.server import mcp

EXPECTED_TOOL_NAMES = {
    "scan_repo",
    "scan_file",
    "scan_diff",
    "get_findings",
    "explain_finding",
    "fix_context",
    "verify_finding",
    "generate_report",
    "get_policy",
    "suppress_finding_tool",
}


def test_server_has_correct_name() -> None:
    """Assert the server name is verix."""
    assert mcp.name == "verix"


def test_all_tools_registered() -> None:
    """Assert all 10 tool names are registered."""
    tools = asyncio.run(mcp.list_tools())
    registered_names = {tool.name for tool in tools}
    assert registered_names == EXPECTED_TOOL_NAMES
