"""Terminal rendering and the full-screen application.

``render`` is pure Rich and has no Textual dependency, so the CLI works
without it. ``app`` is imported lazily by ``lory tui``.
"""

from lory_code_security.ui import render

__all__ = ["render"]
