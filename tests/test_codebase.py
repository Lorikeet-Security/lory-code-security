"""Finding-to-source mapping.

These assert the *plan* (what gets searched) and the search backends against a
temporary tree. They do not assert that the leads are correct — the mapping is
heuristic by construction and the UI labels every hit with the token that
produced it precisely because it can be wrong.
"""

from __future__ import annotations

from lory_code_security.domain.codebase import (
    build_plan,
    locate,
    read_context,
    snippet_for_prompt,
)
from lory_code_security.domain.findings import Finding


def make_finding(**kwargs) -> Finding:
    kwargs.setdefault("id", 1)
    return Finding(**kwargs)


def test_plan_extracts_a_query_parameter():
    finding = make_finding(
        title="Reflected XSS",
        evidence="GET /search?searchTerm=<script>alert(1)</script>",
    )
    assert "searchTerm" in build_plan(finding).literals


def test_plan_extracts_a_named_parameter():
    finding = make_finding(description="The `orderRef` parameter is not validated.")
    assert "orderRef" in build_plan(finding).literals


def test_plan_extracts_a_source_path_from_evidence():
    finding = make_finding(evidence="Traced to app/controllers/search_controller.rb line 42")
    assert "app/controllers/search_controller.rb" in build_plan(finding).literals


def test_plan_extracts_url_path_segments():
    finding = make_finding(affected_asset="https://app.example.com/admin/userExport")
    literals = build_plan(finding).literals
    assert "userExport" in literals


def test_plan_extracts_a_security_header_name():
    finding = make_finding(title="Missing Strict-Transport-Security header")
    assert "Strict-Transport-Security" in build_plan(finding).literals


def test_plan_adds_cwe_sink_patterns():
    assert build_plan(make_finding(cwe_id="CWE-89")).patterns
    assert build_plan(make_finding(cwe_id="CWE-79")).patterns


def test_plan_drops_noise_tokens():
    finding = make_finding(affected_asset="https://www.example.com/api/user")
    literals = [lit.lower() for lit in build_plan(finding).literals]
    for noise in ("www", "com", "api", "user"):
        assert noise not in literals


def test_plan_is_empty_for_a_contentless_finding():
    assert build_plan(make_finding(title="Something")).is_empty()


def test_locate_finds_a_parameter_in_a_temp_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "search.py").write_text(
        "def search(request):\n"
        "    term = request.GET['searchTerm']\n"
        "    return render(term)\n"
    )
    finding = make_finding(evidence="GET /search?searchTerm=payload")
    matches = locate(finding, tmp_path, limit=10)

    assert matches
    assert matches[0].path.name == "search.py"
    assert matches[0].line == 2
    assert matches[0].token == "searchTerm"


def test_locate_skips_vendor_and_node_modules(tmp_path):
    for directory in ("node_modules", "vendor"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "lib.js").write_text("var searchTerm = 1;\n")
    finding = make_finding(evidence="?searchTerm=x")
    assert locate(finding, tmp_path, limit=10) == []


def test_locate_returns_nothing_for_an_empty_plan(tmp_path):
    assert locate(make_finding(title="x"), tmp_path) == []


def test_application_source_outranks_tests(tmp_path):
    for directory in ("src", "tests"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "handler.py").write_text("uniqueMarker = 1\n")
    finding = make_finding(evidence="?uniqueMarker=1")
    matches = locate(finding, tmp_path, limit=10)

    assert len(matches) == 2
    assert matches[0].path.parent.name == "src"


def test_read_context_windows_around_a_line(tmp_path):
    path = tmp_path / "f.py"
    path.write_text("\n".join(f"line{i}" for i in range(1, 21)))
    window = read_context(path, 10, before=2, after=2)

    assert [n for n, _ in window] == [8, 9, 10, 11, 12]
    assert window[2][1] == "line10"


def test_read_context_clamps_at_the_start_of_a_file(tmp_path):
    path = tmp_path / "f.py"
    path.write_text("a\nb\nc\n")
    assert [n for n, _ in read_context(path, 1, before=5, after=1)] == [1, 2]


def test_read_context_on_a_missing_file_is_empty(tmp_path):
    assert read_context(tmp_path / "gone.py", 1) == []


def test_snippet_respects_the_line_budget(tmp_path):
    path = tmp_path / "big.py"
    path.write_text("\n".join(f"line{i}" for i in range(1, 400)))
    finding = make_finding(evidence="?line200=x")
    matches = locate(finding, tmp_path, limit=20)

    snippet = snippet_for_prompt(matches, tmp_path, max_lines=10)
    assert len(snippet.splitlines()) <= 10


def test_snippet_marks_the_matching_line(tmp_path):
    path = tmp_path / "f.py"
    path.write_text("a\nuniqueMarker\nc\n")
    finding = make_finding(evidence="?uniqueMarker=1")
    snippet = snippet_for_prompt(locate(finding, tmp_path), tmp_path)
    assert ">" in snippet and "uniqueMarker" in snippet
