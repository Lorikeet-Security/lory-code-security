"""Clients for the two Lorikeet surfaces a terminal can reach.

* :class:`McpClient` — JSON-RPC over a ``lkmcp_`` bearer token. Findings, the
  knowledge base, scope checks, retests. This is the only credential the tool
  needs.
* :class:`ChatClient` — Lory's public chat endpoint, block format, no
  credential.

The portal's PHP AJAX endpoints are deliberately absent: they authenticate by
PHP session only, so a token-authenticated client cannot use them.
"""

from lory_code_security.client.chat import ChatClient, ChatReply, Conversation
from lory_code_security.client.mcp import McpClient, McpTool, McpToolResult

__all__ = [
    "ChatClient",
    "ChatReply",
    "Conversation",
    "McpClient",
    "McpTool",
    "McpToolResult",
]
