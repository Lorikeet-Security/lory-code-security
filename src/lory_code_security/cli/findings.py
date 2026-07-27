"""Findings commands: list, show, export, trace, triage, retest.

Everything here reads from the platform over MCP (``findings.list`` and
``findings.get``). The local cache is a convenience for offline reading; any
command that acts on a finding re-reads it from the platform first.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import click
from rich.syntax import Syntax
from rich.text import Text

from lory_code_security.cli.common import (
    CONFIG_OPTION,
    console,
    die,
    lexer_for,
    load_config,
    open_store,
)
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    filter_findings,
    severity_counts,
)
from lory_code_security.ui import render


@click.group()
def findings() -> None:
    """List, inspect, and export findings pulled from the platform."""


@findings.command("list")
@CONFIG_OPTION
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--status", help="open | in_progress | resolved | risk_accepted")
@click.option("--asset", "affected_asset", help="Filter to one domain or URL.")
@click.option("--project", "project_id", type=int, help="Filter to one PTaaS project.")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Max rows (the platform caps at 50).")
@click.option("--cached", is_flag=True, help="Read the local cache; do not call the platform.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
def findings_list(
    config_path: str, severity: str | None, status: str | None, affected_asset: str | None,
    project_id: int | None, limit: int, cached: bool, as_json: bool,
) -> None:
    """List findings, most severe first."""
    cfg = load_config(config_path)
    store = open_store(cfg, allow_offline=cached)
    triage_log = TriageLog(cfg.triage_path)

    try:
        if cached:
            rows = filter_findings(store.load_cache(), severity=severity, status=status)
        else:
            rows = store.fetch(
                severity=severity, status=status, project_id=project_id,
                affected_asset=affected_asset, limit=limit,
            )
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps([f.to_dict() for f in rows], indent=2))
        return

    if not rows:
        console.print("[dim]No findings matched.[/dim]")
        return

    console.print(render.render_findings_table(rows, triage_log))
    console.print()
    console.print(render.render_severity_summary(severity_counts(rows)))


@findings.command("show")
@click.argument("finding_id", type=int)
@CONFIG_OPTION
@click.option("--json", "as_json", is_flag=True, help="Emit the raw finding as JSON.")
def findings_show(finding_id: int, config_path: str, as_json: bool) -> None:
    """Show the full body of one finding."""
    cfg = load_config(config_path)
    store = open_store(cfg)
    store.load_cache()

    try:
        finding = store.detail(finding_id)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    if as_json:
        click.echo(json.dumps(finding.to_dict(), indent=2))
        return

    console.print(
        render.render_finding_detail(finding, TriageLog(cfg.triage_path).state(finding.id))
    )


@findings.command("export")
@CONFIG_OPTION
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "markdown"]),
              default="json", show_default=True)
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="Write to a file.")
@click.option("--cached", is_flag=True, help="Export the local cache without refetching.")
def findings_export(config_path: str, fmt: str, out: Path | None, cached: bool) -> None:
    """Export findings as JSON, CSV, or Markdown."""
    cfg = load_config(config_path)
    store = open_store(cfg, allow_offline=cached)

    try:
        rows = store.load_cache() if cached else store.fetch(limit=50)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    text = _export(rows, fmt)
    if out:
        out.write_text(text)
        console.print(f"[green]✓[/green] Wrote {len(rows)} findings to {out}")
    else:
        click.echo(text)


@click.command()
@click.argument("finding_id", type=int)
@CONFIG_OPTION
@click.option("--limit", type=int, default=15, show_default=True, help="Max code leads to show.")
@click.option("--context", type=int, default=0, help="Lines of surrounding source to print.")
def trace(finding_id: int, config_path: str, limit: int, context: int) -> None:
    """Show local source that may be responsible for a finding.

    Heuristic: parameters, routes, and file paths named in the finding are
    grepped against your working tree, plus sink patterns for its CWE. Every
    hit is labelled with the token that produced it, so bad leads are obvious.
    """
    from lory_code_security.domain import codebase

    cfg = load_config(config_path)
    store = open_store(cfg)
    store.load_cache()

    try:
        finding = store.detail(finding_id)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    plan = codebase.build_plan(finding)
    console.print(render.render_finding_header(finding))
    console.print(
        f"\n[dim]Searching {cfg.repo_root} for: "
        f"{', '.join(plan.literals[:8]) or '(no literals derived)'}[/dim]\n"
    )

    matches = codebase.locate(finding, cfg.repo_root, limit=limit, plan=plan)
    if not matches:
        console.print(
            "[yellow]No local code matched.[/yellow] The finding may live in "
            "infrastructure, configuration, or a different repository."
        )
        return

    console.print(render.render_code_matches(matches, cfg.repo_root))

    for match in matches[:5] if context else []:
        window = codebase.read_context(match.path, match.line, context, context)
        if not window:
            continue
        console.print()
        console.print(f"[bold cyan]{match.display(cfg.repo_root)}[/bold cyan]")
        console.print(
            Syntax(
                "\n".join(text for _, text in window),
                lexer_for(match.path),
                line_numbers=True,
                start_line=window[0][0],
                theme="ansi_dark",
                word_wrap=False,
            )
        )


@click.command()
@click.argument("finding_id", type=int)
@click.argument("state", type=click.Choice(["new", "reading", "fixing", "fixed", "wontfix"]))
@CONFIG_OPTION
@click.option("--note", default="", help="Attach a note to the triage entry.")
def triage(finding_id: int, state: str, config_path: str, note: str) -> None:
    """Set your local workflow state on a finding.

    Local only. It never changes the finding's status on the platform — only a
    retest closes a finding upstream.
    """
    cfg = load_config(config_path)
    TriageLog(cfg.triage_path).set_state(finding_id, state, note)
    console.print(
        f"[green]✓[/green] #{finding_id} marked [bold]{state}[/bold] locally "
        f"({cfg.triage_path})"
    )
    if state == "fixed":
        console.print(f"[dim]  Ready for a retest? Run: lory retest {finding_id}[/dim]")


@click.command()
@click.argument("finding_id", type=int)
@CONFIG_OPTION
@click.option("--note", default="", help="What changed and how you fixed it.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def retest(finding_id: int, config_path: str, note: str, yes: bool) -> None:
    """Ask the Lorikeet team to re-test a finding you have fixed.

    This is outward facing: it files a request with a human team.
    """
    cfg = load_config(config_path)
    store = open_store(cfg)
    store.load_cache()

    try:
        finding = store.detail(finding_id)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    console.print(render.render_finding_header(finding))
    if not note:
        note = click.prompt("What changed", default="", show_default=False)
    if not yes:
        click.confirm(
            f"\nFile a retest request for #{finding_id} with the Lorikeet team?", abort=True
        )

    try:
        result = store.request_retest(finding_id, note)
    except LoryConsoleError as exc:
        die(str(exc))
        return

    console.print(f"[green]✓[/green] Retest requested for #{finding_id}")
    console.print(Text(json.dumps(result, indent=2), style="dim"))


# ── helpers ─────────────────────────────────────────────────────────────────


def _export(rows: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([f.to_dict() for f in rows], indent=2)

    if fmt == "csv":
        buffer = io.StringIO()
        columns = ["id", "severity", "status", "title", "affected_asset", "cwe_id", "cvss_score"]
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for finding in rows:
            writer.writerow(finding.to_dict())
        return buffer.getvalue()

    lines = ["# Findings", ""]
    for finding in rows:
        lines.append(f"## #{finding.id} {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity}")
        if finding.cvss_score:
            lines.append(f"- **CVSS:** {finding.cvss_score}")
        if finding.cwe_id:
            lines.append(f"- **CWE:** {finding.cwe_id}")
        if finding.affected_asset:
            lines.append(f"- **Asset:** {finding.affected_asset}")
        if finding.description:
            lines.append(f"\n{finding.description}\n")
        lines.append("")
    return "\n".join(lines)
