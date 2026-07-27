"""lory-code-security — terminal UI and evaluation harness for Lory.

Lory is the Lorikeet Security AI pentester. It is reachable from a terminal on
two documented surfaces:

  * the block-format chat endpoints under ``/ptaas/ajax/`` (public + portal), and
  * the JSON-RPC MCP server at ``/ptaas/mcp/``.

This package wraps both, renders Lory's structured block responses in a
terminal, and provides a scriptable harness for asserting on what comes back.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
