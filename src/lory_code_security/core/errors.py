"""Exception types shared by the clients, the TUI, and the harness."""

from __future__ import annotations


class LoryConsoleError(Exception):
    """Base class for every error this package raises deliberately."""


class ConfigError(LoryConsoleError):
    """config.yml is missing, unreadable, or invalid."""


class TransportError(LoryConsoleError):
    """A network-level failure talking to the platform."""


class AuthError(LoryConsoleError):
    """The MCP bearer token was rejected."""


class ProtocolError(LoryConsoleError):
    """The platform answered, but not in the shape the contract promises."""


class PaywallError(LoryConsoleError):
    """Lory's free-message cap was hit for this session."""

    def __init__(self, message: str, used: int | None = None, limit: int | None = None) -> None:
        super().__init__(message)
        self.used = used
        self.limit = limit


class ToolError(LoryConsoleError):
    """An MCP tool returned ``isError`` or a JSON-RPC error object."""

    def __init__(self, message: str, code: int | None = None, data: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


class AmbiguousFindingError(ToolError):
    """A bare finding id named more than one finding.

    Integer ids collide across the platform's finding stores, so this is the
    normal outcome of typing ``12`` when both ``pentest-12`` and
    ``engagement-12`` exist. Never resolved by guessing.
    """

    def __init__(self, message: str, candidates: list[str] | None = None) -> None:
        super().__init__(message)
        self.candidates = candidates or []
