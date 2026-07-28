"""The cockpit, driven headlessly through Textual's test pilot.

These cover the state bugs that no unit test could reach: the table crashing on
findings that share an integer id, a failed refresh destroying a cached view,
and a table rebuild discarding code leads.
"""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from contextlib import contextmanager  # noqa: E402

from textual.widgets import DataTable, Input, Static  # noqa: E402

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


def _widget_text(app, selector: str) -> str:
    """The text a Static is currently showing."""
    return str(app.query_one(selector, Static).visual)


def _status(app) -> str:
    return _widget_text(app, "#status")


def _counts(app) -> str:
    return _widget_text(app, "#counts")


@contextmanager
def _no_suspend():
    """Stand in for App.suspend(), which a headless driver cannot do."""
    yield


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


@pytest.mark.parametrize("width", [90, 100, 120, 160, 200])
async def test_three_panes_fit_the_terminal(monkeypatch, tmp_path, width):
    """The Lory pane used to run off the right edge, cropping its text mid-word.

    Fixed pane widths plus the middle pane's min-width summed past the
    terminal, and the compositor resolved the overflow by clipping the
    rightmost pane. Text there looked like a wrapping bug; it was a layout one.
    """
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(width, 26)) as pilot:
        await pilot.pause()
        await pilot.press("l")  # reveal the Lory pane
        await pilot.pause()

        panes = [
            app.query_one(sel).size.width
            for sel in ("#sidebar", "#detail-pane", "#lory-pane")
        ]
        assert all(w > 0 for w in panes), panes
        assert sum(panes) <= width, f"panes {panes} sum past a {width}-column terminal"


async def test_the_empty_state_wraps_rather_than_crops(monkeypatch, tmp_path):
    """Every intro line must fit the pane, or words are lost off the edge."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(100, 26)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()

        pane = app.query_one("#lory-pane").size.width
        intro = app.query_one("#lory-intro")
        assert intro.size.width <= pane
        # No hard newlines in the prose: they cannot reflow when the pane shrinks.
        prose = str(app._lory_intro()).split("\n\n")[1]
        assert "\n" not in prose


async def test_the_empty_state_gives_way_to_the_transcript(monkeypatch, tmp_path):
    """The intro used to sit at the top of every conversation forever."""
    from rich.text import Text

    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        assert app.query("#lory-intro")

        app.append_lory(Text("an answer"), role="lory")
        await pilot.pause()

        assert not app.query("#lory-intro")
        assert len(app.query(".lory-message")) == 1


async def test_each_turn_is_labelled_with_its_speaker(monkeypatch, tmp_path):
    from rich.text import Text

    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.append_lory(Text("a question"), role="user")
        app.append_lory(Text("an answer"), role="lory")
        await pilot.pause()

        classes = [set(w.classes) for w in app.query(".lory-message")]
        assert "from-user" in classes[0]
        assert "from-lory" in classes[1]


async def test_a_seeded_ask_echoes_a_summary_not_the_whole_prompt(monkeypatch, tmp_path):
    """Pressing `f` builds a long prompt the user never typed."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))
    sent, echoed = [], []
    monkeypatch.setattr(LoryApp, "lory_worker", lambda self, message: sent.append(message))
    monkeypatch.setattr(
        LoryApp, "append_lory",
        lambda self, renderable, role="lory": echoed.append((role, str(renderable))),
    )

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("f")
        await pilot.pause()

    # The full prompt still goes to Lory...
    assert "I need to fix a security finding" in sent[0]
    assert len(sent[0]) > 200  # ...the whole assembled thing, not the summary

    # ...but the transcript shows the one-line summary.
    role, rendered = echoed[0]
    assert role == "user"
    assert rendered == "Fix pentest-12 · SQL injection"
    assert "I need to fix" not in rendered


async def test_toggling_code_context_updates_the_empty_state(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        assert "off" in str(app._lory_intro())

        await pilot.press("c")
        await pilot.pause()
        assert app.send_code
        assert "on" in str(app._lory_intro())


# ── a rebuild must not move the user off the row they are working on ────────


async def test_marking_a_lower_row_keeps_the_selection(monkeypatch, tmp_path):
    """clear() drops the cursor to row 0, which threw the user back to the top.

    The old test only ever marked the first row, where a reset to row 0 is
    indistinguishable from no reset at all.
    """
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("down", "down")
        await pilot.pause()
        target = app.selected_key
        assert target == "incident-31"

        await pilot.press("m")
        await pilot.pause()

        assert app.triage.state(target) == "fixed"
        assert app.selected_key == target
        assert app.query_one("#findings-table", DataTable).cursor_row == 2


async def test_refreshing_keeps_the_selection(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()

        await pilot.press("r")
        await pilot.pause()
        await pilot.pause()

        assert app.selected_key == "engagement-12"
        assert app.query_one("#findings-table", DataTable).cursor_row == 1


async def test_a_trace_on_a_lower_row_survives_marking_it(monkeypatch, tmp_path):
    """The transient row-0 highlight used to discard the leads on its way past."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=1, text="x", token="q")]
        app.code_matches_key = app.selected_key

        await pilot.press("m")
        await pilot.pause()

        assert app.selected_key == "engagement-12"
        assert len(app.code_matches) == 1


# ── a filter that matches nothing must not leave a live selection ───────────


async def test_a_filter_matching_nothing_clears_the_selection(monkeypatch, tmp_path):
    """f/t/m/R used to act on a finding that was no longer on screen."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.query_one("#filter", Input).focus()
        await pilot.press("z", "z", "z", "enter")
        await pilot.pause()

        assert app.query_one("#findings-table", DataTable).row_count == 0
        assert app.selected_key is None
        assert app.current() is None


async def test_acting_with_no_selection_says_so(monkeypatch, tmp_path):
    """Silence on a keypress reads as a dead key, not as an empty list."""
    store = StubStore(COLLIDING_ROWS)
    app = make_app(monkeypatch, tmp_path, store)

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.query_one("#filter", Input).focus()
        await pilot.press("z", "z", "z", "enter")
        await pilot.pause()

        for key in ("f", "t", "m", "R"):
            app.set_status("")
            await pilot.press(key)
            await pilot.pause()
            assert "no finding selected" in _status(app), key

        assert store.retests == []


async def test_the_counts_line_tracks_the_filter(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        assert _counts(app).startswith("3 findings")

        app.query_one("#filter", Input).focus()
        await pilot.press("x", "s", "s", "enter")
        await pilot.pause()

        # The severity mix still describes the account; the count tracks the view.
        assert _counts(app).startswith("1 of 3 findings")


# ── $EDITOR is a command line, not a program name ───────────────────────────


async def test_an_editor_with_arguments_is_split_not_exec_d_whole(monkeypatch, tmp_path):
    """`EDITOR="code -w"` looked for a program called "code -w" and crashed."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))
    launched: list[list[str]] = []

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=42, text="x", token="q")]

        monkeypatch.setenv("EDITOR", "vim --clean")
        monkeypatch.setattr(app, "suspend", _no_suspend)
        monkeypatch.setattr(
            "subprocess.run", lambda argv, **kw: launched.append(list(argv))
        )
        await pilot.press("e")
        await pilot.pause()

    assert launched == [["vim", "--clean", "+42", str(tmp_path / "a.py")]]


async def test_an_editor_that_will_not_start_is_reported_not_raised(monkeypatch, tmp_path):
    """An unrunnable $EDITOR must not take the cockpit down with it."""
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=1, text="x", token="q")]

        monkeypatch.setenv("EDITOR", "definitely-not-installed")
        monkeypatch.setattr(app, "suspend", _no_suspend)
        await pilot.press("e")
        await pilot.pause()

        assert app.is_running
        assert "could not run $EDITOR" in _status(app)


async def test_a_terminal_that_cannot_suspend_is_reported_not_raised(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.code_matches = [CodeMatch(path=tmp_path / "a.py", line=1, text="x", token="q")]

        # run_test() drives a headless driver, which genuinely cannot suspend.
        await pilot.press("e")
        await pilot.pause()

        assert app.is_running
        assert "cannot suspend" in _status(app)


async def test_marking_one_finding_does_not_mark_its_id_twin(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path, StubStore(COLLIDING_ROWS))

    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        await pilot.press("m")
        await pilot.pause()

        assert app.triage.state("pentest-12") == "fixed"
        assert app.triage.state("engagement-12") == "new"
