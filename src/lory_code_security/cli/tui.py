"""``lory tui`` — launch the full-screen cockpit."""

from __future__ import annotations

import click

from lory_code_security.cli.common import CONFIG_OPTION, die, load_config


@click.command()
@CONFIG_OPTION
@click.option("--cached", is_flag=True, help="Start from the local cache without refetching.")
def tui(config_path: str, cached: bool) -> None:
    """Open the full-screen findings and remediation cockpit."""
    cfg = load_config(config_path)

    try:
        from lory_code_security.ui.app import LoryApp
    except ImportError as exc:
        die(
            f"the TUI needs Textual ({exc}). Install it with:\n"
            "  pip install 'lory-code-security[tui]'   or   pip install textual"
        )
        return

    LoryApp(cfg, start_cached=cached).run()
