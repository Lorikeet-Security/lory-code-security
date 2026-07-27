"""``lory mcp`` and ``lory portal`` — raw access to both platform APIs."""

from __future__ import annotations

import json
from pathlib import Path

import click

from lory_code_security.cli.common import CONFIG_OPTION, console, die, load_config
from lory_code_security.client.mcp import McpClient
from lory_code_security.client.portal import PortalClient
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.ui import render


@click.group()
def mcp() -> None:
    """Raw access to the Lorikeet MCP server (bearer token)."""


@mcp.command("tools")
@CONFIG_OPTION
def mcp_tools(config_path: str) -> None:
    """List the tools your token's scopes unlock."""
    cfg = load_config(config_path)
    try:
        client = McpClient(cfg)
        client.initialize()
        tools = client.list_tools()
    except LoryConsoleError as exc:
        die(str(exc))
        return
    console.print(render.render_tools(tools))


@mcp.command("call")
@click.argument("tool")
@click.argument("args_json", default="{}")
@CONFIG_OPTION
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON rather than a table.")
def mcp_call(tool: str, args_json: str, config_path: str, as_json: bool) -> None:
    """Call one MCP tool. ARGS_JSON is a JSON object of arguments.

    \b
    Example:
      lory mcp call scope.check '{"target": "app.example.com"}'
    """
    cfg = load_config(config_path)
    try:
        arguments = json.loads(args_json)
    except (json.JSONDecodeError, ValueError) as exc:
        die(f"arguments must be a JSON object: {exc}")
        return
    if not isinstance(arguments, dict):
        die("arguments must be a JSON object")
        return

    try:
        client = McpClient(cfg)
        client.initialize()
        result = client.call_tool(tool, arguments)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json or not result.rows():
        click.echo(result.text)
        return
    console.print(render.render_tool_result(result.rows(), result.text))
    console.print(f"\n[dim]{len(result.rows())} rows in {result.elapsed_ms:.0f}ms[/dim]")


@click.group()
def portal() -> None:
    """The portal's PHP endpoints (dashboard session cookie).

    Richer than MCP: full finding bodies, SARIF export, attestation letters.
    """


@portal.command("export")
@CONFIG_OPTION
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "sarif"]),
              default="sarif", show_default=True)
@click.option("--source", type=click.Choice(["all", "ai", "pentest"]), default="all",
              show_default=True, help="Which engine found it.")
@click.option("--severity", multiple=True, help="Filter by severity; repeatable.")
@click.option("--status", help="Filter by status, e.g. open.")
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="Write to a file.")
def portal_export(
    config_path: str, fmt: str, source: str, severity: tuple[str, ...],
    status: str | None, out: Path | None,
) -> None:
    """Export findings from the portal, verbatim.

    SARIF is the useful one: GitHub code scanning and Microsoft Defender both
    ingest it natively, so this turns an engagement into annotations on the
    code without any integration work.

    \b
      lory portal export --format sarif --out findings.sarif
      gh api ... /code-scanning/sarifs -F sarif=@findings.sarif
    """
    cfg = load_config(config_path)
    try:
        text = PortalClient(cfg).export_raw(
            fmt=fmt, source=source, severity=list(severity) or None, status=status
        )
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if out:
        out.write_text(text)
        console.print(f"[green]✓[/green] Wrote {fmt.upper()} export to {out}")
    else:
        click.echo(text)


@portal.command("attestation")
@click.argument("engagement_id", type=int)
@CONFIG_OPTION
@click.option("--type", "engagement_type", type=click.Choice(["ai", "pentest"]),
              default="ai", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["json", "html"]), default="json",
              show_default=True, help="html is print-ready.")
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="Write to a file.")
def portal_attestation(
    engagement_id: int, config_path: str, engagement_type: str, fmt: str, out: Path | None
) -> None:
    """Fetch the attestation letter for an engagement."""
    cfg = load_config(config_path)
    try:
        text = PortalClient(cfg).attestation(engagement_id, engagement_type, fmt)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if out:
        out.write_text(text)
        console.print(f"[green]✓[/green] Wrote attestation for engagement "
                      f"#{engagement_id} to {out}")
    else:
        click.echo(text)


@portal.command("review")
@CONFIG_OPTION
@click.option("--engagement", type=int, help="Limit to one engagement.")
@click.option("--state", default="pending_review", show_default=True,
              help="pending_review | approved | rejected | all")
def portal_review(config_path: str, engagement: int | None, state: str) -> None:
    """List AI findings awaiting human review (staff accounts only)."""
    cfg = load_config(config_path)
    try:
        rows = PortalClient(cfg).review_queue(engagement, state)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if not rows:
        console.print("[dim]Review queue is empty.[/dim]")
        return
    console.print(render.render_tool_result(rows, json.dumps(rows)))
    console.print(f"\n[dim]{len(rows)} findings in state '{state}'[/dim]")
