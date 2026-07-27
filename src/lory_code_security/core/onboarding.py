"""First-run setup.

Users get their credentials from the Lorikeet portal, not from a config file
they hand-write. The portal's MCP page (``/ptaas/dashboard/mcp.php``) mints a
token and shows an ``mcpServers`` JSON block for Claude Code. This module
accepts either — a bare ``lkmcp_`` token, or that whole JSON block pasted in —
verifies it against the live server, and writes ``config.yml``.

If the user already wired Lorikeet into Claude Code, ``discover_mcp_configs``
finds that config and reuses it, so setup is a confirmation rather than a
copy-paste.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from lory_code_security.client.mcp import McpClient
from lory_code_security.core.config import Config
from lory_code_security.core.errors import LoryConsoleError

PORTAL_MCP_PATH = "/ptaas/dashboard/mcp.php"
PORTAL_DOCS_PATH = "/ptaas/dashboard/mcp-docs"

_TOKEN_RE = re.compile(r"lkmcp_[A-Za-z0-9_\-]{8,}")

#: Where an existing Claude Code / Cursor MCP config might already hold a
#: Lorikeet entry. Checked in order; all misses are silent.
_MCP_CONFIG_CANDIDATES = (
    Path.home() / ".claude" / "mcp.json",
    Path.home() / ".claude.json",
    Path(".mcp.json"),
    Path(".cursor") / "mcp.json",
)


@dataclass
class Credentials:
    base_url: str
    token: str
    #: Where these came from, for the "found an existing setup" message.
    source: str = "manual"


def portal_url(base_url: str) -> str:
    return base_url.rstrip("/") + PORTAL_MCP_PATH


def parse_credentials(pasted: str, fallback_base_url: str = "") -> Credentials:
    """Read credentials out of whatever the user pasted.

    Accepts, in order of preference:

    * the portal's ``{"mcpServers": {"lorikeet": {...}}}`` block,
    * a bare ``{"url": ..., "headers": {"Authorization": "Bearer ..."}}`` entry,
    * a raw ``lkmcp_...`` token,
    * a ``curl`` line or anything else containing a token.
    """
    text = (pasted or "").strip()
    if not text:
        raise LoryConsoleError("nothing pasted")

    entry = _find_server_entry(text)
    if entry is not None:
        url = str(entry.get("url") or "")
        headers = entry.get("headers") or {}
        auth = ""
        if isinstance(headers, dict):
            for key, value in headers.items():
                if str(key).lower() == "authorization":
                    auth = str(value)
                    break
        token_match = _TOKEN_RE.search(auth) or _TOKEN_RE.search(text)
        if token_match and url:
            return Credentials(
                base_url=_base_from_mcp_url(url),
                token=token_match.group(0),
                source="pasted mcpServers block",
            )

    token_match = _TOKEN_RE.search(text)
    if not token_match:
        raise LoryConsoleError(
            "no lkmcp_ token found in that. Copy the token or the whole "
            "mcpServers JSON block from the portal's MCP page."
        )

    base_url = fallback_base_url
    url_match = re.search(r"https?://[^\s\"']+", text)
    if url_match:
        base_url = _base_from_mcp_url(url_match.group(0))
    if not base_url:
        raise LoryConsoleError("a token was found but no platform URL; pass --base-url")

    return Credentials(base_url=base_url, token=token_match.group(0), source="pasted token")


def discover_mcp_configs() -> list[Credentials]:
    """Find Lorikeet MCP entries already configured for another agent."""
    found: list[Credentials] = []
    seen: set[tuple[str, str]] = set()

    for path in _MCP_CONFIG_CANDIDATES:
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError, ValueError):
            continue

        for entry in _walk_server_entries(data):
            url = str(entry.get("url") or "")
            if "/mcp" not in url:
                continue
            blob = json.dumps(entry)
            token_match = _TOKEN_RE.search(blob)
            if not token_match:
                continue
            creds = Credentials(
                base_url=_base_from_mcp_url(url),
                token=token_match.group(0),
                source=str(path),
            )
            key = (creds.base_url, creds.token)
            if key not in seen:
                seen.add(key)
                found.append(creds)

    return found


def verify(creds: Credentials, timeout: float = 30.0, verify_tls: bool = True) -> dict[str, Any]:
    """Prove the credentials work before writing them to disk.

    Runs ``initialize`` then ``ping``, and reports which tools the token's
    scopes actually unlock — a token without ``findings:read`` will connect
    happily and then be useless for the whole point of this tool.
    """
    cfg = Config(
        base_url=creds.base_url,
        mcp_token=creds.token,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    client = McpClient(cfg)

    info = client.initialize()
    tools = client.list_tools()
    tool_names = [t.name for t in tools]

    company: Any = None
    if "ping" in tool_names:
        result = client.call_tool("ping", {"echo": "lory-code-security"})
        data = result.structured
        if isinstance(data, dict):
            company = data.get("company_id") or data.get("company")

    return {
        "server": info.get("serverInfo") or {},
        "protocol": info.get("protocolVersion"),
        "tools": tool_names,
        "company_id": company,
        "can_read_findings": "findings.list" in tool_names,
        "can_search_kb": "kb.search" in tool_names,
        "can_request_retest": "retest.request" in tool_names,
    }


def write_config(
    path: Path,
    creds: Credentials,
    surface: str = "portal",
    session_cookie: str | None = None,
    repo_root: str | None = None,
) -> Path:
    """Write config.yml with 0600 permissions.

    The file holds a bearer token, so it is created mode 0600 and the caller is
    expected to keep it out of version control (see .gitignore).
    """
    document: dict[str, Any] = {
        "base_url": creds.base_url,
        "mcp_token": creds.token,
        "surface": surface,
    }
    if session_cookie:
        document["session_cookie"] = session_cookie
    if repo_root:
        document["repo_root"] = repo_root

    path.parent.mkdir(parents=True, exist_ok=True)
    # Create restricted *before* writing, so the token is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(_CONFIG_HEADER)
        yaml.safe_dump(document, f, sort_keys=False, default_flow_style=False)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


_CONFIG_HEADER = """\
# lory-code-security configuration.
#
# Written by `lory init`. This file contains a bearer token: it is mode 0600
# and must stay out of version control.
#
# Every value can be overridden by an environment variable:
#   LORY_BASE_URL  LORY_MCP_TOKEN  LORY_SESSION_COOKIE  LORY_SURFACE
# Use ${VAR} as a value to read it from the environment at load time.

"""


# ── helpers ─────────────────────────────────────────────────────────────────


def _base_from_mcp_url(url: str) -> str:
    """``https://host/ptaas/mcp/`` → ``https://host``."""
    url = url.strip().rstrip("/")
    for suffix in ("/ptaas/mcp", "/mcp"):
        if url.endswith(suffix):
            return url[: -len(suffix)]
    match = re.match(r"^(https?://[^/]+)", url)
    return match.group(1) if match else url


def _find_server_entry(text: str) -> dict[str, Any] | None:
    """Pull the first server object out of a pasted JSON blob."""
    for candidate in _json_candidates(text):
        for entry in _walk_server_entries(candidate):
            if entry.get("url"):
                return entry
    return None


def _json_candidates(text: str) -> list[Any]:
    """Parse the text as JSON, and also try the outermost {...} inside it."""
    out: list[Any] = []
    try:
        out.append(json.loads(text))
    except (json.JSONDecodeError, ValueError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            out.append(json.loads(text[start : end + 1]))
        except (json.JSONDecodeError, ValueError):
            pass
    return out


def _walk_server_entries(data: Any) -> list[dict[str, Any]]:
    """Yield every dict that looks like an MCP server entry."""
    entries: list[dict[str, Any]] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6 or not isinstance(node, dict):
            return
        if "url" in node and isinstance(node.get("url"), str):
            entries.append(node)
        for key, value in node.items():
            if key == "mcpServers" and isinstance(value, dict):
                for server in value.values():
                    if isinstance(server, dict):
                        entries.append(server)
            elif isinstance(value, dict):
                walk(value, depth + 1)

    walk(data)
    return entries
