"""Prompt assembly.

The property that matters most here: source code is attached only on an
explicit opt-in, and the prompt that gets built is the prompt that gets sent.
"""

from __future__ import annotations

from lory_code_security.domain.codebase import locate
from lory_code_security.domain.findings import Finding
from lory_code_security.domain.remediate import (
    MAX_PROMPT_CHARS,
    build_prompt,
    kb_query,
    verification_prompt,
)

FINDING = Finding(
    id=42,
    title="SQL injection in the report filter",
    severity="critical",
    cwe_id="CWE-89",
    cvss_score=9.8,
    affected_asset="https://app.example.com/reports",
    description="The dateFrom parameter is concatenated into the query.",
    evidence="GET /reports?dateFrom=1' OR '1'='1",
)


def test_prompt_carries_the_finding_essentials():
    request = build_prompt(FINDING)
    assert "#42" in request.prompt
    assert "CRITICAL" in request.prompt
    assert "CWE-89" in request.prompt
    assert "app.example.com" in request.prompt


def test_code_is_absent_without_the_opt_in(tmp_path):
    (tmp_path / "q.py").write_text("sql = 'SELECT * FROM r WHERE d=' + dateFrom\n")
    matches = locate(FINDING, tmp_path)

    request = build_prompt(FINDING, matches=matches, repo_root=tmp_path, include_code=False)
    assert not request.included_code
    assert request.code_files == []
    assert "SELECT * FROM r" not in request.prompt


def test_code_is_present_with_the_opt_in(tmp_path):
    (tmp_path / "q.py").write_text("sql = 'SELECT * FROM r WHERE d=' + dateFrom\n")
    matches = locate(FINDING, tmp_path)
    assert matches, "fixture should produce at least one lead"

    request = build_prompt(FINDING, matches=matches, repo_root=tmp_path, include_code=True)
    assert request.included_code
    assert request.code_files
    assert "SELECT * FROM r" in request.prompt


def test_prompt_never_exceeds_the_endpoint_limit():
    """Both chat endpoints substr() the message to 2000 chars server-side."""
    huge = Finding(
        id=1,
        title="x" * 500,
        description="d" * 5000,
        evidence="e" * 5000,
        severity="high",
    )
    request = build_prompt(huge)
    assert len(request.prompt) <= MAX_PROMPT_CHARS
    # Oversized fields are clipped in place rather than dropping the finding.
    assert "#1" in request.prompt
    assert "…" in request.prompt


def test_the_finding_survives_truncation_and_code_is_what_gets_cut(tmp_path):
    """When it will not all fit, the code context goes and the finding stays."""
    # Word-separated padding: an unbroken 32+ char run would be masked by the
    # secret redactor and the section would shrink to nothing.
    padding = " ".join(["filter", "the", "report", "range", "by", "day"] * 12)
    (tmp_path / "q.py").write_text(f"dateFrom = 1  # {padding}\n" * 60)
    huge = Finding(
        id=7, title="SQLi", severity="critical", cwe_id="CWE-89",
        description="d" * 1900, evidence="GET /r?dateFrom=1",
    )
    matches = locate(huge, tmp_path)
    request = build_prompt(
        huge, matches=matches, repo_root=tmp_path, include_code=True, max_context_lines=500
    )

    assert "#7" in request.prompt
    assert "SQLi" in request.prompt
    assert len(request.prompt) <= MAX_PROMPT_CHARS
    assert not request.included_code  # dropped to make room
    assert request.truncated


def test_secrets_in_evidence_are_redacted():
    finding = Finding(
        id=1,
        title="Hardcoded credential",
        severity="high",
        evidence="Found in config: api_key=EXAMPLE0000NOT0000A0000REAL0000KEY0000",
    )
    prompt = build_prompt(finding).prompt
    assert "EXAMPLE0000NOT0000A0000REAL0000KEY0000" not in prompt
    assert "REDACTED" in prompt


def test_kb_query_combines_title_and_cwe():
    query = kb_query(FINDING)
    assert "SQL injection" in query
    assert "CWE-89" in query
    assert len(query) <= 200


def test_a_custom_question_replaces_the_default():
    request = build_prompt(FINDING, question="Just tell me which file to open.")
    assert "Just tell me which file to open." in request.prompt
    assert "skip the general advice" not in request.prompt


def test_verification_prompt_is_bounded():
    prompt = verification_prompt(FINDING, "switched to bound parameters " * 500)
    assert len(prompt) <= MAX_PROMPT_CHARS
    assert "#42" in prompt


def test_describe_states_whether_source_was_attached():
    assert "no source attached" in build_prompt(FINDING).describe()
