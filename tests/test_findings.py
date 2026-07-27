"""Normalisation across the two read paths, plus local triage state."""

from __future__ import annotations

import json

from lory_code_security.domain.findings import (
    Finding,
    TriageLog,
    cwe_number,
    filter_findings,
    severity_counts,
    sort_findings,
)

# What MCP's findings.list returns: flat columns, no body.
MCP_ROW = {
    "id": 12,
    "project_id": 3,
    "title": "Reflected XSS in search",
    "severity": "High",
    "status": "Open",
    "affected_asset": "app.example.com",
    "cwe_id": "CWE-79",
    "cvss_score": 6.1,
}

# What the portal export returns: nested cvss and provenance, full body.
PORTAL_ROW = {
    "id": 12,
    "title": "Reflected XSS in search",
    "severity": "high",
    "cvss": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "status": "open",
    "category": "Injection",
    "cwe": "CWE-79",
    "affected_asset": "app.example.com",
    "description": "The q parameter is reflected unencoded.",
    "evidence": "GET /search?q=<script>alert(1)</script>",
    "remediation": "Encode on output.",
    "provenance": {"source": "lory_ai", "engagement": 41, "vector": "web-xss"},
    "discovered_at": "2026-07-01 10:00:00",
}


def test_mcp_row_normalises():
    finding = Finding.from_row(MCP_ROW)
    assert finding.id == 12
    assert finding.severity == "high"
    assert finding.cwe_id == "CWE-79"
    assert finding.cvss_score == 6.1
    assert not finding.is_detailed  # list view has no body


def test_portal_row_flattens_nested_cvss_and_provenance():
    finding = Finding.from_row(PORTAL_ROW)
    assert finding.cvss_score == 6.1
    assert finding.cvss_vector.startswith("CVSS:3.1/")
    assert finding.cwe_id == "CWE-79"
    assert finding.source == "lory_ai"
    assert finding.engagement_id == 41
    assert finding.vector == "web-xss"
    assert finding.found_by_ai
    assert finding.is_detailed


def test_both_paths_agree_on_the_shared_fields():
    a, b = Finding.from_row(MCP_ROW), Finding.from_row(PORTAL_ROW)
    for field in ("id", "title", "severity", "affected_asset", "cwe_id", "cvss_score"):
        assert getattr(a, field) == getattr(b, field), field


def test_missing_cvss_is_none_not_zero():
    """A finding with no score must not sort as if it scored 0.0 deliberately."""
    assert Finding.from_row({"id": 1, "cvss_score": None}).cvss_score is None
    assert Finding.from_row({"id": 1, "cvss_score": ""}).cvss_score is None


def test_garbage_cvss_does_not_raise():
    assert Finding.from_row({"id": 1, "cvss_score": "n/a"}).cvss_score is None


def test_sort_is_severity_then_cvss_then_id():
    rows = [
        Finding(id=1, severity="low"),
        Finding(id=2, severity="critical", cvss_score=9.1),
        Finding(id=3, severity="critical", cvss_score=9.8),
        Finding(id=4, severity="medium"),
    ]
    assert [f.id for f in sort_findings(rows)] == [3, 2, 4, 1]


def test_unknown_severity_sorts_last():
    rows = [Finding(id=1, severity="weird"), Finding(id=2, severity="info")]
    assert [f.id for f in sort_findings(rows)] == [2, 1]


def test_filter_matches_title_asset_cwe_and_id():
    rows = [Finding.from_row(PORTAL_ROW), Finding(id=99, title="Open redirect")]
    assert len(filter_findings(rows, query="xss")) == 1
    assert len(filter_findings(rows, query="app.example.com")) == 1
    assert len(filter_findings(rows, query="CWE-79")) == 1
    assert len(filter_findings(rows, query="99")) == 1
    assert len(filter_findings(rows, query="nothing-here")) == 0


def test_filter_by_severity():
    rows = [Finding(id=1, severity="high"), Finding(id=2, severity="low")]
    assert [f.id for f in filter_findings(rows, severity="high")] == [1]


def test_severity_counts_covers_every_level():
    counts = severity_counts([Finding(id=1, severity="high"), Finding(id=2, severity="high")])
    assert counts["high"] == 2
    assert counts["critical"] == 0


def test_cwe_number_extraction():
    assert cwe_number("CWE-89") == "89"
    assert cwe_number("cwe 79") == "79"
    assert cwe_number("") == ""
    assert cwe_number("none") == ""


def test_triage_round_trips(tmp_path):
    log = TriageLog(tmp_path / "triage.json")
    assert log.state(7) == "new"

    log.set_state(7, "fixing", note="patching the encoder")
    log.link_files(7, ["src/search.py"])

    reloaded = TriageLog(tmp_path / "triage.json")
    assert reloaded.state(7) == "fixing"
    assert reloaded.note(7) == "patching the encoder"
    assert reloaded.files(7) == ["src/search.py"]


def test_triage_rejects_an_unknown_state(tmp_path):
    log = TriageLog(tmp_path / "triage.json")
    try:
        log.set_state(1, "definitely-fixed-trust-me")
    except ValueError as exc:
        assert "state must be one of" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_triage_survives_a_corrupt_file(tmp_path):
    path = tmp_path / "triage.json"
    path.write_text("{not json")
    assert TriageLog(path).state(1) == "new"


def test_to_dict_is_json_serialisable():
    json.dumps(Finding.from_row(PORTAL_ROW).to_dict())
