"""JSON-RPC client for the Lorikeet Security MCP server.

Endpoint: ``{base_url}/ptaas/mcp/``, bearer-token auth, protocol ``2025-06-18``.
Tokens are minted by ``ptaas/mcp/admin/issue-token.php`` (prefix ``lkmcp_``) or
issued as short-lived OAuth access tokens with the same prefix.

Every tool answers in the MCP standard shape::

    {"content": [{"type": "text", "text": "..."}], "isError": false}

Platform tools put a JSON document in that ``text`` field, so
:attr:`McpToolResult.structured` re-parses it when it parses.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from lory_code_security.core.config import Config
from lory_code_security.core.errors import (
    AuthError,
    LoryConsoleError,
    ProtocolError,
    ToolError,
    TransportError,
)

PROTOCOL_VERSION = "2025-06-18"

#: Tools this client uses, by the scope that unlocks them. Used to explain a
#: scope denial without a round trip.
#:
#: Deliberately not exhaustive: the server may expose more than this, and
#: ``list_tools()`` is always the authority. Legacy tools are left out rather
#: than listed, so nothing here points a user at a surface that is on its way
#: out.
SCOPE_CATALOG: dict[str, tuple[str, ...]] = {
    "findings:read": (
        "findings.search", "findings.detail", "findings.list", "findings.get", "scope.check",
    ),
    "findings:write": ("findings.create", "engagement.update"),
    "kb:read": ("kb.search",),
    "compliance:read": ("compliance.frameworks", "compliance.controls"),
    "retest:request": ("retest.request",),
}


@dataclass
class McpTool:
    name: str
    description: str = ""
    title: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def required_args(self) -> list[str]:
        req = self.input_schema.get("required") or []
        return [str(r) for r in req]

    @property
    def arg_names(self) -> list[str]:
        return list((self.input_schema.get("properties") or {}).keys())

    @property
    def read_only(self) -> bool:
        return bool(self.annotations.get("readOnlyHint"))

    def example_args(self) -> dict[str, Any]:
        """A skeleton argument object, for prefilling the TUI's call box."""
        props = self.input_schema.get("properties") or {}
        out: dict[str, Any] = {}
        for name in self.required_args:
            spec = props.get(name) or {}
            kind = spec.get("type", "string")
            out[name] = 0 if kind in ("integer", "number") else (
                [] if kind == "array" else ("" if kind == "string" else None)
            )
        return out


@dataclass
class McpToolResult:
    tool: str
    content: list[dict[str, Any]] = field(default_factory=list)
    is_error: bool = False
    elapsed_ms: float = 0.0

    @property
    def text(self) -> str:
        return "\n".join(
            str(part.get("text", ""))
            for part in self.content
            if isinstance(part, dict) and part.get("type") == "text"
        )

    @property
    def structured(self) -> Any:
        """The text payload re-parsed as JSON, or ``None`` if it isn't JSON."""
        try:
            return json.loads(self.text)
        except (json.JSONDecodeError, ValueError):
            return None

    def raise_for_error(self) -> None:
        """Raise if the tool set ``isError``, carrying the server's own message.

        MCP reports tool-level failures in the result rather than as a JSON-RPC
        error, so nothing raises on its own. Callers that act on the payload
        must call this first, or a refusal reads as an empty result.
        """
        if self.is_error:
            raise ToolError(self.text.strip() or f"{self.tool} reported an error")

    def rows(self) -> list[dict[str, Any]]:
        """List-shaped tool output as a list of dicts; ``[]`` for anything else."""
        data = self.structured
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("findings", "assets", "results", "controls", "frameworks", "rows"):
                value = data.get(key)
                if isinstance(value, list):
                    return [r for r in value if isinstance(r, dict)]
        return []


class McpClient:
    """One HTTP session against the MCP endpoint."""

    def __init__(self, cfg: Config) -> None:
        if not cfg.mcp_token:
            raise AuthError(
                "no mcp_token configured. Mint one with "
                "ptaas/mcp/admin/issue-token.php, then set LORY_MCP_TOKEN "
                "or mcp_token in config.yml."
            )
        self.cfg = cfg
        self.url = cfg.mcp_url()
        self.token = cfg.mcp_token
        self._id = 0
        self._tools: dict[str, McpTool] | None = None
        self.server_info: dict[str, Any] = {}
        self.instructions: str = ""

    # ── plumbing ────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        from lory_code_security import __version__

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"lory-code-security/{__version__}",
        }

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        body = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            body["params"] = params

        try:
            with httpx.Client(timeout=self.cfg.timeout, verify=self.cfg.verify_tls) as client:
                resp = client.post(self.url, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise TransportError(f"{self.url}: {exc}") from exc

        if resp.status_code in (401, 403):
            challenge = resp.headers.get("www-authenticate", "")
            hint = f" ({challenge})" if challenge else ""
            raise AuthError(f"MCP rejected the bearer token: HTTP {resp.status_code}{hint}")
        if resp.status_code >= 500:
            raise TransportError(f"MCP returned HTTP {resp.status_code}")

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(
                f"MCP returned HTTP {resp.status_code} with a non-JSON body: "
                f"{resp.text[:200]!r}"
            ) from exc

        if isinstance(data, dict) and "error" in data:
            err = data["error"] or {}
            raise ToolError(
                str(err.get("message", "unknown JSON-RPC error")),
                code=err.get("code"),
                data=err.get("data"),
            )
        if not isinstance(data, dict) or "result" not in data:
            raise ProtocolError(f"JSON-RPC response had no 'result': {data}")
        return data["result"]

    # ── protocol ────────────────────────────────────────────────────────────

    def initialize(self, client_name: str = "lory-code-security") -> dict[str, Any]:
        from lory_code_security import __version__

        result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": __version__},
            },
        )
        if isinstance(result, dict):
            self.server_info = result.get("serverInfo") or {}
            self.instructions = str(result.get("instructions") or "")
        return result if isinstance(result, dict) else {}

    def _catalog(self) -> dict[str, McpTool]:
        """Every advertised tool by name, fetched once per session."""
        if self._tools is None:
            try:
                self.list_tools()
            except LoryConsoleError:
                self._tools = {}
        return self._tools or {}

    def has_tool(self, name: str) -> bool:
        """Whether the server exposes a tool, cached for the session.

        Servers are deployed independently of this client, so a newer tool may
        simply not be there yet. Callers use this to pick a path rather than
        discovering the gap through an error.
        """
        return name in self._catalog()

    def tool_accepts(self, name: str, argument: str) -> bool:
        """Whether a tool's advertised schema declares an argument.

        Lets a caller send an optional refinement (a prefixed ``ref`` alongside
        a numeric id, say) only where the server understands it, instead of
        having a strict schema reject the whole call.
        """
        tool = self._catalog().get(name)
        return tool is not None and argument in tool.arg_names

    def list_tools(self) -> list[McpTool]:
        result = self._rpc("tools/list")
        raw = (result or {}).get("tools", []) if isinstance(result, dict) else []
        tools: list[McpTool] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            tools.append(
                McpTool(
                    name=str(entry.get("name", "")),
                    description=str(entry.get("description", "")),
                    title=str(entry.get("title") or entry.get("name", "")),
                    input_schema=entry.get("inputSchema") or {},
                    annotations=entry.get("annotations") or {},
                )
            )
        self._tools = {t.name: t for t in tools}
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> McpToolResult:
        started = time.perf_counter()
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        elapsed = (time.perf_counter() - started) * 1000

        if not isinstance(result, dict) or not isinstance(result.get("content"), list):
            raise ProtocolError(f"tool {name} returned a malformed result: {result}")

        return McpToolResult(
            tool=name,
            content=[c for c in result["content"] if isinstance(c, dict)],
            is_error=bool(result.get("isError")),
            elapsed_ms=elapsed,
        )

    # ── probes ──────────────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        """Hit ``healthz`` and ``readyz``. Neither needs a token."""
        out: dict[str, Any] = {}
        base = self.url.rstrip("/")
        for probe in ("healthz", "readyz"):
            try:
                with httpx.Client(timeout=10.0, verify=self.cfg.verify_tls) as client:
                    resp = client.get(f"{base}/{probe}.php")
                out[probe] = {"status": resp.status_code, "body": resp.text[:200]}
            except httpx.HTTPError as exc:
                out[probe] = {"status": None, "body": str(exc)}
        return out
