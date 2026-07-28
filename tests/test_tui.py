"""The cockpit, driven headlessly through Textual's test pilot.

These cover the state bugs that no unit test could reach: the table crashing on
findings that share an integer id, a failed refresh destroying a cached view,
and a table rebuild discarding code leads.
"""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable  # noqa: E402

from lory_code_security.core.config import Config  # noqa: E402
from lory_code_security.core.errors import TransportError  # noqa: E402
from lory_code_security.domain.codebase import CodeMatch  # noqa: E402
from lory_code_security.domain.findings import Finding, sort_findings  # noqa: E402
from lory_code_security.ui.app import LoryApp  # noqa: E402

COLLIDING_ROWS = [
    {"ref": "pentest-12", "store": "pentest", "id": 12, "severity": "critical",
     "title": "SQL injection", "description": "body", "evidence": "proof"},
    {"ref": "engagement-12", "store": "engagement", "id": 12, "severity": "high",
     "title": "Reflected XSS", "description": "body", "evidence": "proof"},
    {"ref": "incident-31", "store": "incident", "id": 31, "severity": "low",
     "title": "Missing HSTS", "description": "body", "evidence": "proof"},
]


class StubStore:
    def __init__(self, rows, cached=None, fetch_error=None):
        self.rows = rows
        self.cached = cached or []
        self.fetch_error = fetch_error
        self.last_source = "mcp:search"
        self.retests = []

    def load_cache(self):
        return sort_findings([Finding.from_row(r) for r in self.cached])

    def fetch(self, **kwargs):
        if self.fetch_error:
            raise self.fetch_error
        return sort_findings([Finding.from_row(r) for r in self.rows])

    def detail(self, key, refresh=False):
        return next(f for f in (Finding.from_row(r) for r in self.rows) if f.key == key)

    def request_retest(self, finding, note=""):
        self.retests.append(finding.key)
        return {"ok": True}


def make_app(monkeypatch, tmp_path, store) -> LoryApp:
    monkeypatch.setattr(
        "lory_code_security.cli.common.open_store", lambda cfg, allow_offline=False: store
    )
    cfg = Config(
        base_url="https://x.example",
        mcp_token="lkmcp_abcdef012345",
        repo_root=tmp_path,
        state_dir=tmp_path / ".lory_state",
    )
    return LoryApp(cfg)


# ── the crash ───────────────────────────────────────────────────────────────


async def test_findings_sharing_an_id_do_not_crash_the_table(monkeypatch, tmp_path):
    """Keying rows by id raised DuplicateKey and killed the app on startup."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 3
        assert len(app.all_findings) == 3
        assert app.selected_key == "pentest-12"


async def test_moving_the_cursor_selects_by_ref_not_id(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        assert app.selected_key == "pentest-12"
        assert app.current().severity == "critical"

        await pilot.press("down")
        await pilot.pause()
        assert app.selected_key == "engagement-12"
        assert app.current().severity == "high"


# ── a failed refresh must not destroy a good cached view ────────────────────


async def test_a_failed_refresh_keeps_the_cached_findings(monkeypatch, tmp_path):
    store = StubStore(
        COLLIDING_ROWS, cached=COLLIDING_ROWS, fetch_error=TransportError("connection refused")
    )
    app = make_app(monkeypatch, tmp_path, store)

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 3
        assert len(app.all_findings) == 3


async def test_a_failed_refresh_with_no_cache_still_reports_empty(monkeypatch, tmp_path):
    store = StubStore(COLLIDING_ROWS, cached=[], fetch_error=TransportError("refused"))
    app = make_app(monkeypatch, tmp_path, store)

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        assert app.query_one("#findings-table", DataTable).row_count == 0


# ── a table rebuild must not discard code leads ─────────────────────────────


async def test_marking_fixed_keeps_the_code_leads(monkeypatch, tmp_path):
    """apply_filter() re-fires RowHighlighted, which used to clear the trace."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        finding = app.current()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=1, text="x", token="q")]
        app.code_matches_key = finding.key

        await pilot.press("m")
        await pilot.pause()

        assert app.triage.state(finding.key) == "fixed"
        assert len(app.code_matches) == 1
        assert app.selected_key == finding.key


async def test_changing_finding_does_discard_the_code_leads(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=1, text="x", token="q")]
        app.code_matches_key = app.selected_key

        await pilot.press("down")
        await pilot.pause()

        assert app.code_matches == []


# ── triage state is per-finding, not per-id ─────────────────────────────────


async def test_marking_one_finding_does_not_mark_its_id_twin(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("m")
        await pilot.pause()

        assert app.triage.state("pentest-12") == "fixed"
        assert app.triage.state("engagement-12") == "new"
