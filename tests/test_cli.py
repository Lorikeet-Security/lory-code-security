"""The command surface, driven through Click. No network: the store is faked."""

from __future__ import annotations

import json

import pytest
import yaml
from click.testing import CliRunner

from lory_code_security.cli.main import main
from lory_code_security.domain.findings import Finding, FindingStore

COLLIDING_ROWS = [
    {"ref": "pentest-12", "store": "pentest", "id": 12, "severity": "critical",
     "status": "open", "title": "SQL injection in the dateFrom parameter",
     "affected_asset": "https://app.example.com/api/report", "cwe_id": "CWE-89",
     "description": "dateFrom is concatenated into a query.", "evidence": "proof"},
    {"ref": "engagement-12", "store": "engagement", "id": 12, "severity": "high",
     "status": "open", "title": "Reflected XSS in the q parameter",
     "affected_asset": "https://app.example.com/search", "cwe_id": "CWE-79",
     "description": "q is reflected unencoded.", "evidence": "proof"},
    {"ref": "incident-31", "store": "incident", "id": 31, "severity": "low",
     "status": "open", "title": "Missing HSTS", "affected_asset": "https://app.example.com/login",
     "cwe_id": "CWE-319", "description": "No HSTS header.", "evidence": "proof"},
]


class StubStore(FindingStore):
    """A FindingStore that serves canned rows instead of calling the platform."""

    def __init__(self, rows, cache_path=None):
        super().__init__(None, cache_path=cache_path)
        self.rows = rows
        self.retests: list[tuple[str, str]] = []
        for row in rows:
            self._merge(Finding.from_row(row))

    def fetch(self, **kwargs):
        from lory_code_security.domain.findings import sort_findings

        self.last_source = "mcp:search"
        return sort_findings([Finding.from_row(r) for r in self.rows])

    def detail(self, selector, refresh=False):
        return self.resolve(selector)

    def search_kb(self, query, limit=5):
        return []

    def request_retest(self, finding, note=""):
        self.retests.append((finding.key, note))
        return {"ok": True, "ref": finding.key}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A cwd with a valid config and a stubbed store."""
    (tmp_path / "config.yml").write_text(yaml.safe_dump({
        "base_url": "https://x.example",
        "mcp_token": "lkmcp_abcdef012345",
        "repo_root": str(tmp_path),
        "state_dir": str(tmp_path / ".lory_state"),
    }))
    monkeypatch.chdir(tmp_path)

    store = StubStore(COLLIDING_ROWS, cache_path=tmp_path / ".lory_state" / "findings.json")

    # The command modules import open_store by name, so each namespace that
    # holds a reference has to be patched, not just the definition site.
    for module in ("common", "findings", "fix"):
        monkeypatch.setattr(
            f"lory_code_security.cli.{module}.open_store",
            lambda cfg, allow_offline=False: store,
        )
    return store


def run(*args):
    return CliRunner().invoke(main, list(args))


# ── listing and identity ────────────────────────────────────────────────────


def test_list_shows_every_finding_including_id_twins(workspace):
    result = run("findings", "list", "--json")
    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert [r["key"] for r in rows] == ["pentest-12", "engagement-12", "incident-31"]


def test_show_resolves_a_full_ref(workspace):
    result = run("findings", "show", "pentest-12", "--json")
    assert result.exit_code == 0
    assert json.loads(result.output)["severity"] == "critical"

    result = run("findings", "show", "engagement-12", "--json")
    assert json.loads(result.output)["severity"] == "high"


def test_show_refuses_an_ambiguous_bare_id(workspace):
    result = run("findings", "show", "12")
    assert result.exit_code == 1
    assert "names 2 findings" in result.output
    assert "engagement-12" in result.output and "pentest-12" in result.output


def test_show_accepts_an_unambiguous_bare_id(workspace):
    result = run("findings", "show", "31", "--json")
    assert result.exit_code == 0
    assert json.loads(result.output)["key"] == "incident-31"


def test_an_unknown_ref_exits_nonzero(workspace):
    result = run("findings", "show", "nope-999")
    assert result.exit_code == 1
    assert "no finding" in result.output


# ── triage ──────────────────────────────────────────────────────────────────


def test_triage_marks_one_store_not_its_id_twin(workspace, tmp_path):
    assert run("triage", "pentest-12", "fixed").exit_code == 0

    log = json.loads((tmp_path / ".lory_state" / "triage.json").read_text())
    assert log["pentest-12"]["state"] == "fixed"
    assert "engagement-12" not in log


def test_triage_refuses_an_ambiguous_bare_id(workspace):
    result = run("triage", "12", "fixed")
    assert result.exit_code == 1
    assert "names 2 findings" in result.output


def test_triage_rejects_an_unknown_state(workspace):
    assert run("triage", "pentest-12", "definitely-fixed").exit_code != 0


# ── retest ──────────────────────────────────────────────────────────────────


def test_retest_targets_the_resolved_finding(workspace):
    result = run("retest", "engagement-12", "--note", "encoded output", "--yes")
    assert result.exit_code == 0
    assert workspace.retests == [("engagement-12", "encoded output")]
    assert "engagement-12" in result.output


def test_retest_reports_a_platform_refusal_as_a_failure(workspace, monkeypatch):
    from lory_code_security.core.errors import ToolError

    def refuse(finding, note=""):
        raise ToolError("retest denied: engagement is closed")

    monkeypatch.setattr(workspace, "request_retest", refuse)

    result = run("retest", "engagement-12", "--note", "x", "--yes")
    assert result.exit_code == 1
    assert "engagement is closed" in result.output
    assert "Retest requested" not in result.output


# ── export ──────────────────────────────────────────────────────────────────


def test_sarif_export_carries_one_result_per_finding(workspace):
    result = run("findings", "export", "--format", "sarif")
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    refs = [r["properties"]["ref"] for r in doc["runs"][0]["results"]]
    assert refs == ["pentest-12", "engagement-12", "incident-31"]


def test_csv_export_leads_with_the_key(workspace):
    result = run("findings", "export", "--format", "csv")
    assert result.output.splitlines()[0].startswith("key,id,severity")
    assert "pentest-12" in result.output and "engagement-12" in result.output


def test_json_export_round_trips(workspace):
    rows = json.loads(run("findings", "export", "--format", "json").output)
    assert len(rows) == 3


# ── fix ─────────────────────────────────────────────────────────────────────


def test_fix_dry_run_sends_nothing_and_shows_the_prompt(workspace):
    result = run("fix", "pentest-12", "--dry-run", "--no-kb")
    assert result.exit_code == 0
    assert "Prompt (not sent)" in result.output
    assert "dateFrom" in result.output


def test_fix_dry_run_attaches_no_source_without_the_flag(workspace):
    result = run("fix", "pentest-12", "--dry-run", "--no-kb")
    assert "no source attached" in result.output


# ── plumbing ────────────────────────────────────────────────────────────────


def test_version_and_help_work():
    assert "lory-code-security v" in run("--version").output
    assert "GETTING STARTED" in run("--help").output


def test_every_documented_command_is_registered():
    listed = run("--help").output
    for command in ("init", "doctor", "tui", "findings", "trace", "fix",
                    "triage", "retest", "ask", "chat", "mcp", "harness"):
        assert command in listed, command


def test_the_retired_portal_group_is_gone():
    assert run("portal", "export").exit_code != 0
