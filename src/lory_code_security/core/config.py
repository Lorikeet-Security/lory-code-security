"""Configuration loading and validation.

Merges YAML file values with environment variable overrides, the same way
``lk_exporter.config`` does — environment always wins, and ``${VAR}`` tokens in
string values are expanded so secrets can stay out of the file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lory_code_security.core.errors import ConfigError

_ENV_VARS = {
    "base_url": "LORY_BASE_URL",
    "mcp_token": "LORY_MCP_TOKEN",
    "session_cookie": "LORY_SESSION_COOKIE",
    "surface": "LORY_SURFACE",
    "timeout": "LORY_TIMEOUT",
}

# Minted by ptaas/mcp/admin/issue-token.php; OAuth access tokens use the same prefix.
_MCP_TOKEN_RE = re.compile(r"^lkmcp_[A-Za-z0-9_\-]{8,}$")

SURFACES = ("public", "portal")

#: Paths are fixed by the platform layout; they are overridable only for local
#: dev instances that mount the app somewhere other than the document root.
DEFAULT_PATHS = {
    "public_chat": "/ptaas/ajax/lory-public.php",
    "portal_chat": "/ptaas/ajax/lory-chat.php",
    "mcp": "/ptaas/mcp/",
}

STATE_DIR = Path(".lory_state")


@dataclass
class Config:
    base_url: str = "https://lorikeetsecurity.com"
    surface: str = "public"

    # Auth. `mcp_token` unlocks the MCP pane and every `lory mcp` command.
    # `session_cookie` is the PHPSESSID of a logged-in portal session; the
    # portal chat endpoint has no token auth, so this is the only way in.
    mcp_token: str | None = None
    session_cookie: str | None = None
    session_cookie_name: str = "PHPSESSID"

    timeout: float = 60.0
    stream: bool = True
    history_limit: int = 20
    verify_tls: bool = True

    #: The codebase findings are triaged against. Defaults to the working dir.
    repo_root: Path = field(default_factory=Path.cwd)
    #: Send local source excerpts to the platform when asking Lory for a fix.
    #: Off by default: code leaves the machine only when the user says so.
    send_code_context: bool = False
    #: Hard ceiling on how much source one remediation prompt may carry.
    max_context_lines: int = 120

    paths: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PATHS))
    state_dir: Path = field(default=STATE_DIR)

    @property
    def transcript_dir(self) -> Path:
        return self.state_dir / "transcripts"

    @property
    def findings_cache(self) -> Path:
        return self.state_dir / "findings.json"

    @property
    def triage_path(self) -> Path:
        return self.state_dir / "triage.json"

    def chat_url(self, surface: str | None = None) -> str:
        surface = surface or self.surface
        key = "portal_chat" if surface == "portal" else "public_chat"
        return self.base_url.rstrip("/") + self.paths[key]

    def mcp_url(self) -> str:
        return self.base_url.rstrip("/") + self.paths["mcp"]

    def has_mcp(self) -> bool:
        return bool(self.mcp_token)

    def validate(self) -> list[str]:
        errors: list[str] = []

        if not self.base_url:
            errors.append("base_url is required")
        elif not re.match(r"^https?://", self.base_url):
            errors.append("base_url must start with http:// or https://")
        elif self.base_url.startswith("http://") and "localhost" not in self.base_url \
                and not self.base_url.startswith("http://127."):
            errors.append(
                "base_url is plaintext http:// against a non-local host; "
                "the MCP bearer token would go over the wire in the clear"
            )

        if self.surface not in SURFACES:
            errors.append(f"surface must be one of: {', '.join(SURFACES)}")

        if self.surface == "portal" and not self.session_cookie:
            errors.append(
                "surface 'portal' needs session_cookie — the portal chat endpoint "
                "authenticates by dashboard session, not by token"
            )

        if self.mcp_token and not _MCP_TOKEN_RE.match(self.mcp_token):
            errors.append("mcp_token must look like lkmcp_<token>")

        if self.timeout <= 0:
            errors.append("timeout must be greater than 0")

        if self.history_limit < 0:
            errors.append("history_limit must be >= 0")
        elif self.history_limit > 20:
            errors.append(
                "history_limit above 20 is pointless — the chat endpoints slice "
                "history to the last 20 turns server-side"
            )

        if not self.repo_root.is_dir():
            errors.append(f"repo_root is not a directory: {self.repo_root}")

        if self.max_context_lines < 1:
            errors.append("max_context_lines must be >= 1")

        for key in DEFAULT_PATHS:
            if key not in self.paths:
                errors.append(f"paths.{key} is missing")
            elif not str(self.paths[key]).startswith("/"):
                errors.append(f"paths.{key} must be an absolute path beginning with /")

        return errors


def _resolve_env(value: Any) -> Any:
    """Expand a whole-string ``${VAR}`` token."""
    if not isinstance(value, str):
        return value
    m = re.fullmatch(r"\$\{(\w+)\}", value.strip())
    if m:
        return os.environ.get(m.group(1), "")
    return value


def load(config_path: str | Path = "config.yml") -> Config:
    """Load config from YAML plus environment overrides.

    A missing file is not an error: every field has a default, and the common
    case of `LORY_BASE_URL` + `LORY_MCP_TOKEN` in the environment needs no file
    at all.
    """
    path = Path(config_path)
    raw: dict[str, Any] = {}

    if path.exists():
        try:
            with path.open() as f:
                raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"{path} must contain a YAML mapping at the top level")

    def get(key: str, default: Any = None) -> Any:
        env_key = _ENV_VARS.get(key)
        if env_key and os.environ.get(env_key):
            return os.environ[env_key]
        return _resolve_env(raw.get(key, default))

    paths = dict(DEFAULT_PATHS)
    for key, value in (raw.get("paths") or {}).items():
        paths[key] = str(value)

    try:
        timeout = float(get("timeout", 60.0))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"timeout must be a number: {exc}") from exc

    repo_root = get("repo_root") or os.environ.get("LORY_REPO_ROOT") or "."
    state_dir = raw.get("state_dir")

    return Config(
        base_url=str(get("base_url", "https://lorikeetsecurity.com")).rstrip("/"),
        surface=str(get("surface", "public")).lower(),
        mcp_token=get("mcp_token") or None,
        session_cookie=get("session_cookie") or None,
        session_cookie_name=str(raw.get("session_cookie_name", "PHPSESSID")),
        timeout=timeout,
        stream=bool(raw.get("stream", True)),
        history_limit=int(raw.get("history_limit", 20)),
        verify_tls=bool(raw.get("verify_tls", True)),
        repo_root=Path(str(repo_root)).expanduser().resolve(),
        send_code_context=bool(raw.get("send_code_context", False)),
        max_context_lines=int(raw.get("max_context_lines", 120)),
        paths=paths,
        state_dir=Path(state_dir) if state_dir else STATE_DIR,
    )


def load_checked(config_path: str | Path = "config.yml") -> Config:
    """Load and raise ``ConfigError`` if anything is invalid."""
    cfg = load(config_path)
    errors = cfg.validate()
    if errors:
        raise ConfigError("invalid configuration:\n  - " + "\n  - ".join(errors))
    return cfg
