"""``lory mcp`` — raw access to the MCP server."""

from __future__ import annotations

import json

import click

from lory_code_security.cli.common import CONFIG_OPTION, console, die, load_config
from lory_code_security.client.mcp import McpClient
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
