"""Shared plumbing for the command modules."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console

from lory_code_security.client.mcp import McpClient
from lory_code_security.client.portal import PortalClient
from lory_code_security.core.config import Config, load_checked
from lory_code_security.core.errors import ConfigError, LoryConsoleError
from lory_code_security.domain.findings import FindingStore

console = Console()
err_console = Console(stderr=True)

CONFIG_OPTION = click.option(
    "--config", "config_path", default="config.yml", show_default=True,
    envvar="LORY_CONFIG", help="Path to the YAML config file.",
)


def die(message: str) -> None:
    """Print an error and exit non-zero."""
    err_console.print(f"[bold red]error:[/bold red] {message}")
    sys.exit(1)


def load_config(config_path: str) -> Config:
    try:
        return load_checked(config_path)
    except ConfigError as exc:
        die(f"{exc}\n\nRun `lory init` to set up, or `lory doctor` to diagnose.")
        raise  # unreachable; keeps type checkers happy


def open_store(cfg: Config, allow_offline: bool = False) -> FindingStore:
    """Build a FindingStore with whichever read paths are configured.

    Both are optional individually but at least one is required: the portal
    export needs a session cookie, MCP needs a token. The store prefers the
    portal (full bodies, 5000 rows) and falls back to MCP.
    """
    client: McpClient | None = None
    portal: PortalClient | None = None

    if cfg.has_mcp():
        try:
            client = McpClient(cfg)
            client.initialize()
        except LoryConsoleError as exc:
            if not allow_offline and not cfg.session_cookie:
                die(str(exc))
            client = None

    if cfg.session_cookie:
        try:
            portal = PortalClient(cfg)
        except LoryConsoleError:
            portal = None

    if client is None and portal is None and not allow_offline:
        die(
            "no way to read findings. Run `lory init` to set up an MCP token, "
            "or add a session_cookie for the portal export."
        )

    return FindingStore(client, portal=portal, cache_path=cfg.findings_cache)


def detect_repo_root() -> Path:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return Path.cwd()


def lexer_for(path: Path) -> str:
    """Rich/Pygments lexer name for a source file."""
    return {
        ".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript",
        ".tsx": "tsx", ".php": "php", ".rb": "ruby", ".go": "go", ".java": "java",
        ".cs": "csharp", ".rs": "rust", ".sql": "sql", ".html": "html",
        ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".sh": "bash",
    }.get(path.suffix.lower(), "text")
