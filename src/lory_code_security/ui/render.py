"""Rich renderers for Lory's block format and MCP tool output.

Lory's blocks were designed for a web chat widget: charts are Chart.js,
invoices are Stripe links, CTAs are buttons. None of that exists in a
terminal, so each block gets a text-native equivalent that keeps the
information and drops the interactivity — a chart becomes a bar gauge, a CTA
becomes a labelled URL. Transactional blocks (invoice, booking, handoff) are
deliberately loud, because in the terminal there is no visual button to make
it obvious that Lory just tried to charge someone.
"""

from __future__ import annotations

import json
from typing import Any

from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from lory_code_security.domain.blocks import Block

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
    "info": "dim cyan",
}

BLOCK_STYLES = {
    "text": "white",
    "list": "white",
    "pricing": "cyan",
    "link": "blue",
    "cta": "bold cyan",
    "table": "white",
    "chart": "magenta",
    "report": "green",
    "invoice": "bold yellow",
    "booking": "bold green",
    "handoff": "bold red",
}

_BAR_CHARS = "▏▎▍▌▋▊▉█"


def render_block(block: Block, width: int = 88) -> RenderableType:
    """Turn one block into something a terminal can show."""
    handler = _HANDLERS.get(block.type)
    if handler is None:
        return Panel(
            _json_text(block.data),
            title=f"[dim]unknown block: {block.type}[/dim]",
            border_style="red",
            width=width,
        )
    return handler(block, width)


def render_reply(
    blocks: list[Block], suggestions: list[str] | None = None, width: int = 88
) -> RenderableType:
    parts: list[RenderableType] = [render_block(b, width) for b in blocks]
    if suggestions:
        parts.append(render_suggestions(suggestions))
    return Group(*parts) if parts else Text("(empty reply)", style="dim")


def render_suggestions(suggestions: list[str]) -> RenderableType:
    chips = [Text(f" {s} ", style="black on bright_cyan") for s in suggestions]
    return Group(Text(""), Columns(chips, padding=(0, 1)))


# ── per-block renderers ─────────────────────────────────────────────────────


def _text(block: Block, width: int) -> RenderableType:
    return Text(str(block.get("content", "")), style="white")


def _list(block: Block, width: int) -> RenderableType:
    items = block.get("items") or []
    if not isinstance(items, list):
        return Text(str(items))
    body = Text()
    for item in items:
        body.append("  • ", style="cyan")
        body.append(f"{item}\n")
    return body


def _pricing(block: Block, width: int) -> RenderableType:
    body = Text()
    body.append(f"{block.get('price', '?')}", style="bold green")
    timeline = block.get("timeline")
    if timeline:
        body.append(f"   {timeline}", style="dim")
    description = block.get("description")
    if description:
        body.append(f"\n{description}", style="white")
    return Panel(
        body,
        title=f"[bold]{block.get('service', 'Service')}[/bold]",
        border_style="cyan",
        width=width,
    )


def _link(block: Block, width: int) -> RenderableType:
    body = Text()
    body.append("🔗 ", style="blue")
    body.append(str(block.get("title", "")), style="bold blue underline")
    body.append(f"\n   {block.get('url', '')}", style="dim blue")
    description = block.get("description")
    if description:
        body.append(f"\n   {description}", style="dim")
    return body


def _cta(block: Block, width: int) -> RenderableType:
    body = Text()
    body.append(f"▸ {block.get('label', 'Continue')}", style="bold cyan")
    body.append(f"   {block.get('url', '')}", style="dim")
    return Panel(body, border_style="cyan", width=width)


def _table(block: Block, width: int) -> RenderableType:
    headers = block.get("headers") or []
    rows = block.get("rows") or []
    table = Table(box=None, header_style="bold cyan", pad_edge=False, expand=False)
    for header in headers:
        table.add_column(str(header))
    for row in rows:
        cells = row if isinstance(row, list) else [row]
        table.add_row(*[str(c) for c in cells])
    return table


def _chart(block: Block, width: int) -> RenderableType:
    """Chart.js has no terminal equivalent, so render a labelled bar gauge."""
    labels = [str(v) for v in (block.get("labels") or [])]
    values: list[float] = []
    for v in block.get("data") or []:
        try:
            values.append(float(v))
        except (TypeError, ValueError):
            values.append(0.0)

    if not labels or not values:
        return Panel(_json_text(block.data), border_style="magenta", width=width)

    peak = max(values) or 1.0
    label_width = min(max((len(label) for label in labels), default=6), 22)
    bar_width = max(10, width - label_width - 16)

    body = Text()
    for label, value in zip(labels, values, strict=False):
        body.append(f"{label[:label_width]:<{label_width}} ", style="white")
        body.append(_bar(value / peak, bar_width), style=_severity_style(label) or "magenta")
        body.append(f" {_num(value)}\n", style="bold")

    title = str(block.get("title") or block.get("chart_type") or "Chart")
    return Panel(body, title=f"[bold]{title}[/bold]", border_style="magenta", width=width)


def _report(block: Block, width: int) -> RenderableType:
    sections = block.get("sections") or []
    body = Text()
    generated = block.get("generated")
    if generated:
        body.append(f"generated {generated}\n\n", style="dim")
    for section in sections:
        if not isinstance(section, dict):
            continue
        body.append(f"{section.get('heading', '')}\n", style="bold green")
        body.append(f"{section.get('content', '')}\n\n", style="white")
    return Panel(
        body,
        title=f"[bold green]{block.get('title', 'Report')}[/bold green]",
        border_style="green",
        width=width,
    )


def _invoice(block: Block, width: int) -> RenderableType:
    body = Text()
    body.append("Lory generated a payable Stripe invoice.\n\n", style="bold yellow")
    body.append(f"{block.get('service', '?')}\n", style="bold white")
    body.append(f"{block.get('price', '?')}\n", style="bold green")
    detail = " / ".join(
        str(block.get(k)) for k in ("service_type", "tier") if block.get(k)
    )
    if detail:
        body.append(f"{detail}\n", style="dim")
    description = block.get("description")
    if description:
        body.append(f"{description}\n", style="white")
    return Panel(
        body, title="[bold yellow]⚠ INVOICE[/bold yellow]", border_style="yellow", width=width
    )


def _booking(block: Block, width: int) -> RenderableType:
    body = Text("Lory opened a consultation booking.\n", style="bold green")
    context = block.get("context")
    if context:
        body.append(f"\ncontext: {context}", style="dim")
    return Panel(body, title="[bold green]BOOKING[/bold green]", border_style="green", width=width)


def _handoff(block: Block, width: int) -> RenderableType:
    body = Text("Lory escalated this conversation to a human.\n", style="bold red")
    context = block.get("context")
    if context:
        body.append(f"\ncontext: {context}", style="dim")
    return Panel(body, title="[bold red]⚠ HANDOFF[/bold red]", border_style="red", width=width)


_HANDLERS = {
    "text": _text,
    "list": _list,
    "pricing": _pricing,
    "link": _link,
    "cta": _cta,
    "table": _table,
    "chart": _chart,
    "report": _report,
    "invoice": _invoice,
    "booking": _booking,
    "handoff": _handoff,
}


# ── MCP output ──────────────────────────────────────────────────────────────


def render_tool_result(
    rows: list[dict[str, Any]], raw_text: str, max_rows: int = 50
) -> RenderableType:
    """Render list-shaped MCP output as a table, anything else as JSON."""
    if not rows:
        return _json_text(raw_text)

    columns = _pick_columns(rows)
    table = Table(box=None, header_style="bold cyan", pad_edge=False)
    for column in columns:
        table.add_column(column.replace("_", " "))

    for row in rows[:max_rows]:
        cells: list[Text] = []
        for column in columns:
            value = row.get(column)
            text = "" if value is None else str(value)
            style = _severity_style(text) if column == "severity" else None
            cells.append(Text(text[:60], style=style or ""))
        table.add_row(*cells)

    if len(rows) > max_rows:
        return Group(table, Text(f"\n… {len(rows) - max_rows} more rows", style="dim"))
    return table


def render_tools(tools: list[Any]) -> RenderableType:
    table = Table(box=None, header_style="bold cyan", pad_edge=False)
    table.add_column("tool")
    table.add_column("required")
    table.add_column("description")
    for tool in tools:
        table.add_row(
            Text(tool.name, style="bold"),
            Text(", ".join(tool.required_args) or "—", style="dim"),
            Text(_first_sentence(tool.description), style="white"),
        )
    return table


def render_problems(problems: list[str], title: str = "Contract violations") -> RenderableType:
    body = Text()
    for problem in problems:
        body.append("  ✗ ", style="bold red")
        body.append(f"{problem}\n", style="red")
    return Panel(body, title=f"[bold red]{title}[/bold red]", border_style="red")


def section(title: str) -> RenderableType:
    return Rule(f"[bold]{title}[/bold]", style="dim")


# ── findings ────────────────────────────────────────────────────────────────

TRIAGE_STYLES = {
    "new": "dim",
    "reading": "cyan",
    "fixing": "bold yellow",
    "fixed": "bold green",
    "wontfix": "dim strike",
}


def severity_text(severity: str) -> Text:
    severity = (severity or "info").lower()
    return Text(severity.upper()[:4], style=SEVERITY_STYLES.get(severity, "dim"))


def render_findings_table(findings: list[Any], triage: Any = None) -> RenderableType:
    """The triage list: severity, id, title, asset, and local workflow state."""
    table = Table(box=None, header_style="bold cyan", pad_edge=False, expand=True)
    table.add_column("sev", width=4, no_wrap=True)
    table.add_column("id", width=6, justify="right", no_wrap=True)
    table.add_column("title", ratio=3)
    table.add_column("asset", ratio=2, no_wrap=True)
    table.add_column("cwe", width=9, no_wrap=True)
    table.add_column("state", width=8, no_wrap=True)

    for finding in findings:
        state = triage.state(finding.id) if triage is not None else ""
        table.add_row(
            severity_text(finding.severity),
            Text(str(finding.id), style="dim"),
            Text(finding.title or "(untitled)"),
            Text(finding.affected_asset or "—", style="dim"),
            Text(finding.cwe_id or "—", style="dim"),
            Text(state, style=TRIAGE_STYLES.get(state, "dim")) if state else Text(""),
        )
    return table


def render_severity_summary(counts: dict[str, int]) -> RenderableType:
    parts: list[Text] = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts.get(severity, 0)
        if not count:
            continue
        chunk = Text()
        chunk.append(f" {count} ", style=SEVERITY_STYLES.get(severity, "dim"))
        chunk.append(f" {severity}", style="dim")
        parts.append(chunk)
    total = sum(counts.values())
    if not parts:
        return Text(f"{total} findings", style="dim")
    return Columns([*parts, Text(f"  ({total} total)", style="dim")], padding=(0, 2))


def render_finding_header(finding: Any) -> RenderableType:
    head = Text()
    head.append(f"#{finding.id}  ", style="dim")
    head.append(f"{finding.title}\n", style="bold white")
    head.append(
        f"{finding.severity.upper()}",
        style=SEVERITY_STYLES.get(finding.severity.lower(), "dim"),
    )
    if finding.cvss_score:
        head.append(f"   CVSS {finding.cvss_score}", style="bold")
    if finding.cwe_id:
        head.append(f"   {finding.cwe_id}", style="dim")
    if finding.affected_asset:
        head.append(f"\n{finding.affected_asset}", style="cyan")
    return Panel(head, border_style=_severity_border(finding.severity))


def render_finding_detail(finding: Any, triage_state: str = "") -> RenderableType:
    parts: list[RenderableType] = [render_finding_header(finding)]

    meta = Table(box=None, show_header=False, pad_edge=False)
    meta.add_column(style="dim", width=12)
    meta.add_column()
    for label, value in (
        ("status", finding.status),
        ("category", finding.category),
        ("cvss", finding.cvss_vector),
        ("found", finding.discovered_at),
        ("project", finding.project_id),
        ("local", triage_state),
    ):
        if value not in (None, "", 0):
            style = TRIAGE_STYLES.get(str(value), "white") if label == "local" else "white"
            meta.add_row(label, Text(str(value), style=style))
    parts.append(meta)

    for title, body, style in (
        ("Description", finding.description, "white"),
        ("Evidence", finding.evidence, "dim"),
        ("Remediation", finding.remediation, "green"),
    ):
        if body:
            parts.append(Text(""))
            parts.append(Rule(f"[bold]{title}[/bold]", style="dim", align="left"))
            parts.append(Text(body, style=style))

    return Group(*parts)


def render_code_matches(matches: list[Any], root: Any) -> RenderableType:
    """Code leads, each labelled with the token that produced it."""
    table = Table(box=None, header_style="bold cyan", pad_edge=False, expand=True)
    table.add_column("location", ratio=2, no_wrap=True)
    table.add_column("matched on", width=18, no_wrap=True)
    table.add_column("line", ratio=3)

    for match in matches:
        table.add_row(
            Text(match.display(root), style="bold cyan"),
            Text(str(match.token)[:18], style="dim"),
            Text(match.text[:120], style="white"),
        )
    return table


def _severity_border(severity: str) -> str:
    return {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "green", "info": "cyan",
    }.get((severity or "").lower(), "dim")


# ── helpers ─────────────────────────────────────────────────────────────────


def _bar(fraction: float, width: int) -> str:
    fraction = max(0.0, min(1.0, fraction))
    filled = fraction * width
    whole = int(filled)
    remainder = filled - whole
    bar = "█" * whole
    if whole < width and remainder > 0:
        bar += _BAR_CHARS[min(len(_BAR_CHARS) - 1, int(remainder * len(_BAR_CHARS)))]
    return bar.ljust(width, " ")


def _num(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.1f}"


def _severity_style(value: str) -> str | None:
    return SEVERITY_STYLES.get(str(value).strip().lower())


def _pick_columns(rows: list[dict[str, Any]], limit: int = 7) -> list[str]:
    """Prefer the identifying columns; fall back to insertion order."""
    preferred = (
        "id", "severity", "status", "title", "affected_asset", "asset",
        "verdict", "framework", "control", "source", "cvss_score", "category",
    )
    seen: list[str] = []
    for key in preferred:
        if any(key in row for row in rows):
            seen.append(key)
    for row in rows:
        for key in row:
            if key not in seen:
                seen.append(key)
    return seen[:limit]


def _first_sentence(text: str, limit: int = 90) -> str:
    text = " ".join((text or "").split())
    head = text.split(". ")[0]
    return head if len(head) <= limit else head[: limit - 1] + "…"


def _json_text(value: Any) -> Text:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return Text(value, style="white")
    return Text(json.dumps(value, indent=2, ensure_ascii=False), style="white")
