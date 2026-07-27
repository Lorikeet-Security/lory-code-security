"""The findings cockpit.

Three columns:

* **left** — every finding on the account, severity-ordered, filterable.
* **middle** — the selected finding, plus the local code that may cause it.
* **right** — Lory, seeded with the selected finding when you press ``f``.

Network calls run in Textual workers so the UI never blocks on the platform.
Nothing here scans anything: findings arrive from the portal, already reviewed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from lory_code_security.client.chat import ChatClient, Conversation
from lory_code_security.core.config import Config
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.domain import codebase, remediate
from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    filter_findings,
    severity_counts,
)
from lory_code_security.ui import render

SEVERITY_COLOURS = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
    "info": "dim cyan",
}


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no gate for anything that leaves the machine."""

    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n,escape", "cancel", "No"),
    ]

    def __init__(self, question: str, detail: str = "") -> None:
        super().__init__()
        self.question = question
        self.detail = detail

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label(self.question, id="confirm-question")
            if self.detail:
                yield Static(self.detail, id="confirm-detail")
            yield Label("[bold]y[/bold] confirm    [bold]n[/bold] cancel")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class LoryApp(App[None]):
    """Findings triage and remediation, full screen."""

    CSS_PATH = "app.tcss"
    TITLE = "lory-code-security"

    BINDINGS = [
        Binding("q,ctrl+c", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("f", "ask_lory", "Fix with Lory"),
        Binding("t", "trace_code", "Trace code"),
        Binding("l", "toggle_lory", "Lory pane"),
        Binding("m", "mark_fixed", "Mark fixed"),
        Binding("R", "request_retest", "Request retest"),
        Binding("e", "open_editor", "Open in $EDITOR"),
        Binding("c", "toggle_code_context", "Code context"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
    ]

    findings: reactive[list[Finding]] = reactive(list, always_update=True)
    selected_id: reactive[int | None] = reactive(None)

    def __init__(self, cfg: Config, start_cached: bool = False) -> None:
        super().__init__()
        self.cfg = cfg
        self.start_cached = start_cached
        self.store: Any = None
        self.triage = TriageLog(cfg.triage_path)
        self.conversation: Conversation | None = None
        self.all_findings: list[Finding] = []
        self.code_matches: list[codebase.CodeMatch] = []
        self.filter_text = ""
        self.send_code = cfg.send_code_context

    # ── layout ──────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("FINDINGS", classes="pane-title")
                yield Input(placeholder="filter…", id="filter")
                yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=False)
                yield Static("", id="counts")
            with Vertical(id="detail-pane"):
                yield Static("DETAIL", classes="pane-title")
                yield RichLog(id="detail", wrap=True, markup=True, highlight=False)
            with Vertical(id="lory-pane"):
                yield Static("LORY", classes="pane-title")
                yield RichLog(id="lory-log", wrap=True, markup=True, highlight=False)
                yield Input(placeholder="ask Lory…", id="lory-input")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_column("sev", width=4)
        table.add_column("id", width=6)
        table.add_column("title", width=24)
        table.add_column("st", width=3)
        table.focus()

        self.status(f"{self.cfg.base_url} · repo {self.cfg.repo_root.name}")
        self.load_findings(refresh=not self.start_cached)

    # ── data ────────────────────────────────────────────────────────────────

    @work(thread=True, exclusive=True, group="load")
    def load_findings(self, refresh: bool = True) -> None:
        from lory_code_security.cli.common import open_store

        if self.store is None:
            try:
                self.store = open_store(self.cfg, allow_offline=True)
            except SystemExit:
                self.call_from_thread(self.status, "no read path configured — run `lory init`")
                return

        cached = self.store.load_cache()
        if cached:
            self.call_from_thread(self.set_findings, cached, "cache")

        if not refresh:
            return

        self.call_from_thread(self.status, "fetching findings…")
        try:
            rows = self.store.fetch(limit=50)
        except LoryConsoleError as exc:
            self.call_from_thread(self.status, f"fetch failed: {exc}")
            return
        self.call_from_thread(self.set_findings, rows, self.store.last_source)

    def set_findings(self, rows: list[Finding], source: str) -> None:
        self.all_findings = rows
        self.apply_filter()
        counts = severity_counts(rows)
        summary = "  ".join(
            f"{counts[s]} {s[0].upper()}" for s in ("critical", "high", "medium", "low", "info")
            if counts.get(s)
        )
        self.query_one("#counts", Static).update(f"{len(rows)} findings   {summary}")
        self.status(f"{len(rows)} findings via {source}")

    def apply_filter(self) -> None:
        rows = filter_findings(self.all_findings, query=self.filter_text)
        self.findings = rows

        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for finding in rows:
            state = self.triage.state(finding.id)
            table.add_row(
                Text(finding.severity.upper()[:4],
                     style=SEVERITY_COLOURS.get(finding.severity, "dim")),
                Text(str(finding.id), style="dim"),
                Text(finding.title or "(untitled)"),
                Text(_state_glyph(state), style="bold green" if state == "fixed" else "yellow"),
                key=str(finding.id),
            )
        if rows and self.selected_id is None:
            self.selected_id = rows[0].id
            self.show_detail(rows[0])

    def current(self) -> Finding | None:
        if self.selected_id is None:
            return None
        for finding in self.all_findings:
            if finding.id == self.selected_id:
                return finding
        return None

    # ── events ──────────────────────────────────────────────────────────────

    @on(DataTable.RowHighlighted, "#findings-table")
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        self.selected_id = int(event.row_key.value)
        self.code_matches = []
        finding = self.current()
        if finding is not None:
            self.show_detail(finding)
            if not finding.is_detailed:
                self.load_detail(finding.id)

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        self.filter_text = event.value.strip()
        self.apply_filter()
        self.query_one("#findings-table", DataTable).focus()

    @on(Input.Submitted, "#lory-input")
    def _lory_submitted(self, event: Input.Submitted) -> None:
        message = event.value.strip()
        if not message:
            return
        event.input.value = ""
        self.send_to_lory(message)

    # ── detail rendering ────────────────────────────────────────────────────

    def show_detail(self, finding: Finding) -> None:
        log = self.query_one("#detail", RichLog)
        log.clear()
        log.write(render.render_finding_detail(finding, self.triage.state(finding.id)))

        if finding.source:
            log.write(Text(f"\nfound by: {finding.source}"
                           + (f"  ·  vector {finding.vector}" if finding.vector else ""),
                           style="dim"))
        if self.code_matches:
            log.write(Text("\nLocal code leads", style="bold"))
            log.write(render.render_code_matches(self.code_matches, self.cfg.repo_root))

    @work(thread=True, group="detail")
    def load_detail(self, finding_id: int) -> None:
        if self.store is None:
            return
        try:
            finding = self.store.detail(finding_id)
        except LoryConsoleError as exc:
            self.call_from_thread(self.status, f"detail failed: {exc}")
            return
        for i, existing in enumerate(self.all_findings):
            if existing.id == finding.id:
                self.all_findings[i] = finding
                break
        if self.selected_id == finding_id:
            self.call_from_thread(self.show_detail, finding)

    # ── actions ─────────────────────────────────────────────────────────────

    def action_refresh(self) -> None:
        self.load_findings(refresh=True)

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_clear_filter(self) -> None:
        self.query_one("#filter", Input).value = ""
        self.filter_text = ""
        self.apply_filter()

    def action_toggle_lory(self) -> None:
        pane = self.query_one("#lory-pane")
        pane.set_class(not pane.has_class("visible"), "visible")

    def action_toggle_code_context(self) -> None:
        self.send_code = not self.send_code
        self.status(
            "code context ON — source will be sent with fix requests"
            if self.send_code
            else "code context OFF"
        )

    def action_trace_code(self) -> None:
        finding = self.current()
        if finding is None:
            return
        self.status("searching the working tree…")
        self.trace_worker(finding)

    @work(thread=True, group="trace")
    def trace_worker(self, finding: Finding) -> None:
        matches = codebase.locate(finding, self.cfg.repo_root, limit=15)
        self.code_matches = matches
        self.call_from_thread(self.show_detail, finding)
        self.call_from_thread(
            self.status,
            f"{len(matches)} code lead(s) in {self.cfg.repo_root}" if matches
            else "no local code matched this finding",
        )

    def action_ask_lory(self) -> None:
        finding = self.current()
        if finding is None:
            return

        pane = self.query_one("#lory-pane")
        pane.add_class("visible")

        request = remediate.build_prompt(
            finding,
            matches=self.code_matches,
            repo_root=self.cfg.repo_root,
            include_code=self.send_code,
            max_context_lines=self.cfg.max_context_lines,
        )

        if request.included_code:
            self.push_screen(
                ConfirmScreen(
                    f"Send source from {len(request.code_files)} file(s) to Lory?",
                    ", ".join(request.code_files),
                ),
                lambda ok: self.send_to_lory(request.prompt) if ok else None,
            )
        else:
            self.send_to_lory(request.prompt)

    def action_mark_fixed(self) -> None:
        finding = self.current()
        if finding is None:
            return
        state = "new" if self.triage.state(finding.id) == "fixed" else "fixed"
        self.triage.set_state(finding.id, state)
        self.apply_filter()
        self.status(f"#{finding.id} marked {state} locally (not on the platform)")

    def action_request_retest(self) -> None:
        finding = self.current()
        if finding is None or self.store is None:
            return
        self.push_screen(
            ConfirmScreen(
                f"File a retest request for #{finding.id} with the Lorikeet team?",
                finding.title,
            ),
            lambda ok: self.retest_worker(finding.id) if ok else None,
        )

    @work(thread=True, group="retest")
    def retest_worker(self, finding_id: int) -> None:
        try:
            self.store.request_retest(finding_id, "Requested from lory-code-security")
        except LoryConsoleError as exc:
            self.call_from_thread(self.status, f"retest failed: {exc}")
            return
        self.call_from_thread(self.status, f"retest requested for #{finding_id}")

    def action_open_editor(self) -> None:
        """Open the top code lead in $EDITOR, suspending the TUI."""
        import os
        import subprocess

        if not self.code_matches:
            self.status("no code leads yet — press t to trace")
            return

        editor = os.environ.get("EDITOR", "vi")
        match = self.code_matches[0]
        target = _editor_target(editor, match.path, match.line)
        with self.suspend():
            subprocess.run([editor, *target], check=False)

    # ── Lory ────────────────────────────────────────────────────────────────

    def send_to_lory(self, message: str) -> None:
        pane = self.query_one("#lory-pane")
        pane.add_class("visible")
        log = self.query_one("#lory-log", RichLog)
        log.write(Text(f"\n› {message[:300]}", style="bold cyan"))
        self.lory_worker(message)

    @work(thread=True, group="lory")
    def lory_worker(self, message: str) -> None:
        if self.conversation is None:
            surface, warning = remediate.recommended_surface(self.cfg.surface)
            self.conversation = Conversation(ChatClient(self.cfg, surface))
            if warning:
                self.call_from_thread(self._lory_write, Text(warning, style="yellow"))

        self.call_from_thread(self.status, "asking Lory…")
        try:
            reply = self.conversation.send(message, stream=False)
        except LoryConsoleError as exc:
            self.call_from_thread(self._lory_write, Text(f"error: {exc}", style="red"))
            self.call_from_thread(self.status, "Lory request failed")
            return

        self.call_from_thread(
            self._lory_write, render.render_reply(reply.blocks, reply.suggestions, width=48)
        )
        self.call_from_thread(self.status, f"Lory replied in {reply.elapsed_ms / 1000:.1f}s")

    def _lory_write(self, renderable: Any) -> None:
        self.query_one("#lory-log", RichLog).write(renderable)

    # ── misc ────────────────────────────────────────────────────────────────

    def status(self, message: str) -> None:
        self.query_one("#status", Static).update(message)


def _state_glyph(state: str) -> str:
    return {
        "new": "", "reading": "·", "fixing": "~", "fixed": "✓", "wontfix": "×",
    }.get(state, "")


def _editor_target(editor: str, path: Path, line: int) -> list[str]:
    """Build the jump-to-line argument for the common editors."""
    name = Path(editor).name
    if name in ("vi", "vim", "nvim"):
        return [f"+{line}", str(path)]
    if name in ("code", "codium", "cursor"):
        return ["--goto", f"{path}:{line}"]
    if name in ("emacs", "emacsclient"):
        return [f"+{line}", str(path)]
    if name in ("nano", "micro"):
        return [f"+{line}", str(path)]
    return [str(path)]
