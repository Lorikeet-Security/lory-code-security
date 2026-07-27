"""lory-code-security — terminal UI and evaluation harness for Lory.

Lory is the Lorikeet Security AI pentester. Everything here runs on one
credential — the ``lkmcp_`` bearer token from your portal's MCP page:

  * the JSON-RPC MCP server at ``/ptaas/mcp/`` for findings, the knowledge
    base, scope checks, and retests, and
  * Lory's public chat endpoint for remediation answers, which needs no
    credential because the prompt carries the finding.

This package wraps both, renders Lory's structured block responses in a
terminal, and provides a scriptable harness for asserting on what comes back.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
