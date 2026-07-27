"""Exception types shared by the clients, the TUI, and the harness."""

from __future__ import annotations


class LoryConsoleError(Exception):
    """Base class for every error this package raises deliberately."""


class ConfigError(LoryConsoleError):
    """config.yml is missing, unreadable, or invalid."""


class TransportError(LoryConsoleError):
    """A network-level failure talking to the platform."""


class AuthError(LoryConsoleError):
    """The MCP token or portal session cookie was rejected."""


class ProtocolError(LoryConsoleError):
    """The platform answered, but not in the shape the contract promises."""


class PaywallError(LoryConsoleError):
    """The portal chat free-message cap was hit for this session."""

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
