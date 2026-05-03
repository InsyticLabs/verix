from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from verix.mcp.server import get_policy, suppress_finding_tool
from verix.policy.models import VerixConfig


def test_get_policy_returns_json() -> None:
    """Assert get_policy returns valid JSON with a version key."""
    result = get_policy()
    parsed = json.loads(result)
    assert "version" in parsed


def test_get_policy_returns_defaults_when_no_file() -> None:
    """Assert get_policy returns defaults when config file is missing."""
    result = get_policy("nonexistent.yaml")
    parsed = json.loads(result)
    assert parsed["version"] == 1


def test_suppress_finding_tool_returns_error_when_finding_not_found() -> None:
    """Assert suppress_finding_tool returns an error when finding is missing."""
    with patch("verix.mcp.server.load_scan_cache", return_value=[]):
        result = suppress_finding_tool(finding_id="VX-9999", reason="test")
        parsed = json.loads(result)
        assert "error" in parsed


def test_suppress_finding_tool_suppresses_successfully() -> None:
    """Assert suppress_finding_tool suppresses a finding and returns success."""
    finding = MagicMock()
    finding.vx_id = "VX-0001"
    finding.fingerprint = "abc123"
    finding.scanner.rule_id = "rule-1"
    finding.location.path = "src/app.py"

    with patch("verix.mcp.server.load_scan_cache", return_value=[finding]):
        with patch("verix.mcp.server.load_policy", return_value=VerixConfig()):
            with patch("verix.mcp.server.save_policy") as mock_save:
                result = suppress_finding_tool(
                    finding_id="VX-0001",
                    reason="false positive",
                )
                parsed = json.loads(result)
                assert parsed["suppressed"] == "VX-0001"
                mock_save.assert_called_once()
