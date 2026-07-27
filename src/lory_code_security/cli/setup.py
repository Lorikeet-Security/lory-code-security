"""``lory init`` and ``lory doctor`` — getting connected and proving it works."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.panel import Panel
from rich.text import Text

from lory_code_security.cli.common import (
    CONFIG_OPTION,
    console,
    detect_repo_root,
    die,
)
from lory_code_security.client.mcp import McpClient
from lory_code_security.core import onboarding
from lory_code_security.core.config import load
from lory_code_security.core.errors import ConfigError, LoryConsoleError


@click.command()
@CONFIG_OPTION
@click.option("--base-url", default=None, help="Platform URL, e.g. https://lorikeetsecurity.com")
@click.option("--token", default=None, help="Non-interactive: pass the lkmcp_ token directly.")
@click.option("--force", is_flag=True, help="Overwrite an existing config file.")
def init(config_path: str, base_url: str | None, token: str | None, force: bool) -> None:
    """Set up lory-code-security from your Lorikeet portal.

    Everything you need is on the portal's MCP page: it mints a token and shows
    the JSON block you would paste into Claude Code. Paste either one here.

    If you have already connected Lorikeet to Claude Code or Cursor, this finds
    that config and offers to reuse it.
    """
    path = Path(config_path)
    if path.exists() and not force:
        click.confirm(f"{path} already exists. Overwrite it?", abort=True)

    default_base = base_url or "https://lorikeetsecurity.com"
    creds: onboarding.Credentials | None = None

    if token:
        creds = onboarding.Credentials(base_url=default_base, token=token, source="--token")
    else:
        creds = _pick_existing_credentials()

    if creds is None:
        base = (base_url or click.prompt("Platform URL", default=default_base)).strip()
        console.print()
        console.print(
            Panel(
                Text.from_markup(
                    "Open your Lorikeet portal and go to the MCP page:\n\n"
                    f"  [bold cyan]{onboarding.portal_url(base)}[/bold cyan]\n\n"
                    "Create a token with at least the [bold]findings:read[/bold] scope "
                    "(add [bold]kb:read[/bold] and [bold]retest:request[/bold] for "
                    "remediation lookups and retest requests).\n\n"
                    "Then copy either the token itself or the whole "
                    "[bold]mcpServers[/bold] JSON block, and paste it below."
                ),
                title="[bold]Step 1 — get a token from the portal[/bold]",
                border_style="cyan",
            )
        )
        console.print()
        pasted = _prompt_multiline("Paste token or JSON block (blank line to finish)")
        try:
            creds = onboarding.parse_credentials(pasted, fallback_base_url=base)
        except LoryConsoleError as exc:
            die(str(exc))

    console.print(f"\nVerifying against [bold]{creds.base_url}[/bold] …")
    try:
        report = onboarding.verify(creds)
    except LoryConsoleError as exc:
        die(f"the token did not work: {exc}")
        return

    server = report["server"] or {}
    console.print(
        f"[green]✓[/green] Connected to {server.get('name', 'the MCP server')} "
        f"{server.get('version', '')}".rstrip()
    )
    if report["company_id"]:
        console.print(
            f"[green]✓[/green] Authenticated as company [bold]{report['company_id']}[/bold]"
        )
    console.print(f"[green]✓[/green] {len(report['tools'])} tools available")

    if not report["can_read_findings"]:
        console.print(
            "[yellow]![/yellow] This token has no [bold]findings:read[/bold] scope. "
            "Findings triage will not work — mint a new token with that scope."
        )
    if not report["can_search_kb"]:
        console.print(
            "[dim]  No kb:read scope; remediation answers will not include "
            "knowledge base entries.[/dim]"
        )
    if not report["can_request_retest"]:
        console.print("[dim]  No retest:request scope; `lory retest` will not work.[/dim]")

    repo_root = detect_repo_root()
    onboarding.write_config(path, creds, repo_root=str(repo_root))
    console.print(f"\n[green]\u2713[/green] Wrote [bold]{path}[/bold] (mode 0600)")
    console.print(f"[dim]  repo_root: {repo_root}[/dim]")
    console.print("\nNext: [bold]lory doctor[/bold], then [bold]lory tui[/bold]")


@click.command()
@CONFIG_OPTION
def doctor(config_path: str) -> None:
    """Check configuration, connectivity, token scopes, and repo detection."""
    ok = True

    try:
        cfg = load(config_path)
    except ConfigError as exc:
        die(str(exc))
        return

    path = Path(config_path)
    if path.exists():
        console.print(f"[green]✓[/green] Config loaded from {config_path}")
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            console.print(
                f"[yellow]![/yellow] {config_path} is mode {mode:o} and holds a token; "
                f"run: chmod 600 {config_path}"
            )
    else:
        console.print(f"[dim]  No {config_path}; using defaults and environment.[/dim]")

    errors = cfg.validate()
    if errors:
        for e in errors:
            console.print(f"[red]✗[/red] {e}")
        ok = False
    else:
        console.print("[green]✓[/green] Config is valid")

    console.print(f"[green]✓[/green] Platform: {cfg.base_url}")
    console.print(f"[green]✓[/green] Repo root: {cfg.repo_root}")
    if not (cfg.repo_root / ".git").exists():
        console.print("[dim]  Not a git repo; code search falls back to a filesystem walk.[/dim]")

    if not cfg.has_mcp():
        console.print("[red]✗[/red] No mcp_token — findings are unavailable. Run: lory init")
        ok = False
    else:
        try:
            client = McpClient(cfg)
            client.initialize()
            tools = [t.name for t in client.list_tools()]
            console.print(f"[green]✓[/green] MCP connected, {len(tools)} tools")
            for tool, label in (
                ("findings.list", "findings triage"),
                ("kb.search", "remediation lookups"),
                ("retest.request", "retest requests"),
            ):
                present = tool in tools
                mark = "[green]✓[/green]" if present else "[yellow]![/yellow]"
                state = "available" if present else "NOT in this token's scopes"
                console.print(f"{mark} {tool} ({label}): {state}")
                if tool == "findings.list" and not present:
                    ok = False
        except LoryConsoleError as exc:
            console.print(f"[red]✗[/red] MCP: {exc}")
            ok = False

    if cfg.retired_keys:
        console.print(
            f"[yellow]![/yellow] {config_path} still carries keys this version "
            f"no longer reads: {', '.join(cfg.retired_keys)}. Harmless, but you "
            "can delete them."
        )

    console.print(
        f"\n[dim]Code context: {'ON' if cfg.send_code_context else 'OFF'} — source "
        f"{'is' if cfg.send_code_context else 'is not'} sent with fix requests.[/dim]"
    )
    console.print(f"\n[bold {'green' if ok else 'red'}]{'Ready.' if ok else 'Not ready.'}[/]")
    sys.exit(0 if ok else 1)


# ── helpers ─────────────────────────────────────────────────────────────────


def _pick_existing_credentials() -> onboarding.Credentials | None:
    found = onboarding.discover_mcp_configs()
    if not found:
        return None

    console.print("\n[bold]Found an existing Lorikeet MCP connection:[/bold]")
    for i, creds in enumerate(found, 1):
        console.print(f"  {i}. {creds.base_url}  [dim]({creds.source})[/dim]")

    if not click.confirm("\nReuse it?", default=True):
        return None
    if len(found) == 1:
        return found[0]
    index = click.prompt("Which one", type=click.IntRange(1, len(found)), default=1)
    return found[index - 1]


def _prompt_multiline(label: str) -> str:
    console.print(f"[bold]{label}:[/bold]")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip() and lines:
            break
        if line.strip():
            lines.append(line)
    return "\n".join(lines)
