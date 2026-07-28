"""What the runner observes from a step, and how checks read it."""

from __future__ import annotations

from lory_code_security.client.mcp import McpToolResult
from lory_code_security.core.config import Config
from lory_code_security.harness.checks import run_check
from lory_code_security.harness.runner import Runner
from lory_code_security.harness.scenario import Step


class FakeMcpClient:
    def __init__(self, result: McpToolResult) -> None:
        self.result = result

    def initialize(self):
        return {}

    def call_tool(self, name, args):
        return self.result


def observe_mcp(result: McpToolResult):
    runner = Runner(Config(base_url="https://x.example", mcp_token="lkmcp_abcdef012345"))
    runner._mcp = FakeMcpClient(result)
    return runner._observe_mcp(Step(kind="mcp", target="findings.get"))


def tool_error(text: str) -> McpToolResult:
    return McpToolResult(
        tool="findings.get", content=[{"type": "text", "text": text}], is_error=True
    )


def test_a_tool_error_keeps_the_servers_message():
    """`expect: - error: "required"` had nothing to match before this."""
    obs = observe_mcp(tool_error("Missing required argument: id"))
    assert not obs.ok
    assert obs.error == "Missing required argument: id"


def test_the_error_check_can_now_match_a_tool_level_message():
    obs = observe_mcp(tool_error("Missing required argument: id"))
    assert run_check("error", obs, {"value": "required"}).passed
    assert not run_check("error", obs, {"value": "nonsense"}).passed


def test_an_empty_tool_error_still_reports_something():
    obs = observe_mcp(McpToolResult(tool="findings.get", content=[], is_error=True))
    assert obs.error == "tool reported isError"
    assert run_check("error", obs, {}).passed


def test_a_healthy_call_is_observed_as_ok():
    result = McpToolResult(
        tool="findings.search",
        content=[{"type": "text", "text": '[{"id": 1, "severity": "high"}]'}],
    )
    obs = observe_mcp(result)
    assert obs.ok
    assert obs.error is None
    assert run_check("row_count", obs, {"min": 1, "max": 1}).passed
    assert run_check("json_path", obs, {"path": "[0].severity", "equals": "high"}).passed
