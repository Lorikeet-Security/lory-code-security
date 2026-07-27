"""Clients for the three Lorikeet surfaces reachable from a terminal.

* :class:`McpClient` -- JSON-RPC over a ``lkmcp_`` bearer token. Tenant-scoped,
  headless, CI-friendly.
* :class:`PortalClient` -- the portal's PHP AJAX endpoints over a dashboard
  session cookie. Richer findings data, SARIF export, attestation letters.
* :class:`ChatClient` -- Lory's conversational endpoints, block format.
"""

from lory_code_security.client.chat import ChatClient, ChatReply, Conversation
from lory_code_security.client.mcp import McpClient, McpTool, McpToolResult
from lory_code_security.client.portal import ExportResult, PortalClient

__all__ = [
    "ChatClient",
    "ChatReply",
    "Conversation",
    "ExportResult",
    "McpClient",
    "McpTool",
    "McpToolResult",
    "PortalClient",
]
