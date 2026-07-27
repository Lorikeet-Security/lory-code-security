"""``lory ask`` and ``lory chat`` — talking to Lory directly."""

from __future__ import annotations

import json
from typing import Any

import click
from rich.panel import Panel
from rich.text import Text

from lory_code_security.cli.common import CONFIG_OPTION, console, die, load_config
from lory_code_security.client.chat import ChatClient, Conversation
from lory_code_security.core.errors import LoryConsoleError, PaywallError
from lory_code_security.ui import render


@click.command()
@click.argument("message", nargs=-1, required=True)
@CONFIG_OPTION
@click.option("--json", "as_json", is_flag=True, help="Emit the raw reply as JSON.")
def ask(message: tuple[str, ...], config_path: str, as_json: bool) -> None:
    """Ask Lory one question and print the answer."""
    cfg = load_config(config_path)
    try:
        reply = ChatClient(cfg).send(" ".join(message), stream=False)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps(reply.raw, indent=2))
        return
    console.print(render.render_reply(reply.blocks, reply.suggestions))


@click.command()
@CONFIG_OPTION
@click.option("--no-stream", is_flag=True, help="Wait for the whole reply instead of streaming.")
def chat(config_path: str, no_stream: bool) -> None:
    """Interactive chat with Lory. Ctrl-D or /quit to exit."""
    cfg = load_config(config_path)
    conversation = Conversation(ChatClient(cfg))

    console.print(
        Panel(
            Text.from_markup(
                "Chatting with Lory.\n"
                "[dim]/quit to exit, /clear to reset history, /raw for the last JSON.[/dim]"
            ),
            border_style="cyan",
        )
    )

    last: Any = None
    while True:
        try:
            message = console.input("\n[bold cyan]you ›[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye[/dim]")
            return

        if not message:
            continue
        if message in ("/quit", "/exit"):
            return
        if message == "/clear":
            conversation.clear()
            console.print("[dim]history cleared[/dim]")
            continue
        if message == "/raw":
            console.print(Text(json.dumps(getattr(last, "raw", {}), indent=2), style="dim"))
            continue

        console.print()
        try:
            if no_stream or not cfg.stream:
                reply = conversation.send(message, stream=False)
                console.print(render.render_reply(reply.blocks, reply.suggestions))
            else:
                reply = conversation.stream(
                    message, on_block=lambda b: console.print(render.render_block(b))
                )
                if reply.suggestions:
                    console.print(render.render_suggestions(reply.suggestions))
            last = reply
        except PaywallError as exc:
            console.print(f"[yellow]paywall:[/yellow] {exc}")
        except LoryConsoleError as exc:
            console.print(f"[red]error:[/red] {exc}")
