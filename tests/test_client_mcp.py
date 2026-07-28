"""The MCP client, over a mock transport. No network."""

from __future__ import annotations

import json

import httpx
import pytest

from lory_code_security.client.mcp import McpClient, McpToolResult
from lory_code_security.core.config import Config
from lory_code_security.core.errors import AuthError, ProtocolError, ToolError, TransportError

TOOLS = [
    {"name": "findings.search", "description": "Search every store.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
    {"name": "retest.request", "description": "Ask for a retest.",
     "inputSchema": {"type": "object",
                     "properties": {"finding_id": {"type": "integer"}, "ref": {"type": "string"}},
                     "required": ["finding_id"]}},
]


def client_with(handler, **overrides) -> McpClient:
    """An McpClient whose HTTP calls are served by `handler`.

    ``_rpc`` builds a fresh ``httpx.Client`` per request, so the module
    reference is swapped for a stub that hands back a mock-backed one. The
    autouse fixture below puts the real module back.
    """
    import lory_code_security.client.mcp as mcp_module

    cfg = Config(base_url="https://x.example", mcp_token="lkmcp_abcdef012345", **overrides)
    client = McpClient(cfg)
    mcp_module.httpx = _StubHttpx(httpx.MockTransport(handler))
    return client


class _StubHttpx:
    """Stands in for the httpx module so _rpc gets a mock-backed Client."""

    HTTPError = httpx.HTTPError
    Response = httpx.Response

    def __init__(self, transport: httpx.MockTransport) -> None:
        self._transport = transport

    def Client(self, **kwargs):  # noqa: N802 - mirrors httpx.Client
        return httpx.Client(transport=self._transport)


@pytest.fixture(autouse=True)
def restore_httpx():
    import lory_code_security.client.mcp as mcp_module

    original = mcp_module.httpx
    yield
    mcp_module.httpx = original


def rpc_ok(result):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": result})

    return handler


# ── result shape ────────────────────────────────────────────────────────────


def test_raise_for_error_carries_the_servers_own_message():
    result = McpToolResult(
        tool="findings.get",
        content=[{"type": "text", "text": "id is required"}],
        is_error=True,
    )
    with pytest.raises(ToolError, match="id is required"):
        result.raise_for_error()


def test_raise_for_error_falls_back_to_naming_the_tool():
    result = McpToolResult(tool="findings.get", content=[], is_error=True)
    with pytest.raises(ToolError, match="findings.get reported an error"):
        result.raise_for_error()


def test_a_healthy_result_does_not_raise():
    McpToolResult(tool="ping", content=[{"type": "text", "text": "{}"}]).raise_for_error()


def test_rows_unwraps_the_common_envelopes():
    def result(payload):
        return McpToolResult(tool="t", content=[{"type": "text", "text": json.dumps(payload)}])

    assert result([{"id": 1}]).rows() == [{"id": 1}]
    assert result({"findings": [{"id": 2}]}).rows() == [{"id": 2}]
    assert result({"nothing": "here"}).rows() == []
    assert McpToolResult(tool="t", content=[{"type": "text", "text": "plain"}]).rows() == []


# ── protocol ────────────────────────────────────────────────────────────────


def test_initialize_records_the_server_info():
    client = client_with(rpc_ok({
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": "lorikeet-mcp", "version": "2.1.0"},
        "instructions": "Tenant scoped.",
    }))
    client.initialize()
    assert client.server_info["name"] == "lorikeet-mcp"
    assert client.instructions == "Tenant scoped."


def test_tool_accepts_reads_the_advertised_schema():
    client = client_with(rpc_ok({"tools": TOOLS}))
    assert client.has_tool("findings.search")
    assert not client.has_tool("findings.nope")
    assert client.tool_accepts("retest.request", "ref")
    assert not client.tool_accepts("retest.request", "surface")
    assert not client.tool_accepts("findings.nope", "ref")


def test_the_tool_catalog_is_fetched_once():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body["method"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                         "result": {"tools": TOOLS}})

    client = client_with(handler)
    client.has_tool("findings.search")
    client.has_tool("retest.request")
    client.tool_accepts("retest.request", "ref")
    assert calls.count("tools/list") == 1


def test_call_tool_surfaces_is_error_without_raising():
    client = client_with(rpc_ok({
        "content": [{"type": "text", "text": "severity is invalid"}], "isError": True,
    }))
    result = client.call_tool("findings.list", {"severity": "apocalyptic"})
    assert result.is_error
    assert result.text == "severity is invalid"


# ── failure modes ───────────────────────────────────────────────────────────


def test_a_401_is_an_auth_error():
    client = client_with(lambda r: httpx.Response(401, headers={"www-authenticate": "Bearer"}))
    with pytest.raises(AuthError, match="401"):
        client.initialize()


def test_a_500_is_a_transport_error():
    client = client_with(lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(TransportError, match="500"):
        client.initialize()


def test_a_json_rpc_error_object_becomes_a_tool_error():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": body["id"],
            "error": {"code": -32601, "message": "Unknown tool: nope"},
        })

    client = client_with(handler)
    with pytest.raises(ToolError, match="Unknown tool") as excinfo:
        client.call_tool("nope", {})
    assert excinfo.value.code == -32601


def test_a_non_json_body_is_a_protocol_error():
    client = client_with(lambda r: httpx.Response(200, text="<html>login</html>"))
    with pytest.raises(ProtocolError, match="non-JSON"):
        client.initialize()


def test_a_result_without_content_is_a_protocol_error():
    client = client_with(rpc_ok({"unexpected": True}))
    with pytest.raises(ProtocolError, match="malformed"):
        client.call_tool("ping", {})


def test_the_bearer_token_is_sent():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        body = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})

    client_with(handler).initialize()
    assert seen["auth"] == "Bearer lkmcp_abcdef012345"


def test_a_client_without_a_token_refuses_to_build():
    with pytest.raises(AuthError, match="no mcp_token"):
        McpClient(Config(base_url="https://x.example"))
