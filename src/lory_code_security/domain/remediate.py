"""Turn a finding into a remediation question for Lory.

The flow is: take a finding, optionally attach local code leads and knowledge
base entries, build one prompt, send it to Lory, and render the answer.

Two things this module is careful about:

**What leaves the machine.** Source code is attached only when the caller
passes ``include_code=True`` (config ``send_code_context``, CLI ``--code``).
:func:`build_prompt` returns the exact string that will be sent, so the TUI and
CLI can show it before anything is transmitted. There is no hidden path that
uploads source.

**What the model is told.** Lory's chat endpoint has no access to your
engagement, so everything it needs is put in the message: the finding, its
evidence, and the knowledge base entries fetched over MCP. That is what keeps
the answer grounded in *this* finding rather than generic advice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lory_code_security.domain.codebase import CodeMatch, snippet_for_prompt
from lory_code_security.domain.findings import Finding

MAX_PROMPT_CHARS = 2000  # both chat endpoints substr() the message to this

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


@dataclass
class RemediationRequest:
    """Everything that will be sent, assembled and inspectable."""

    finding: Finding
    prompt: str
    included_code: bool = False
    code_files: list[str] = field(default_factory=list)
    kb_titles: list[str] = field(default_factory=list)
    truncated: bool = False

    def describe(self) -> str:
        bits = [f"{len(self.prompt)} chars"]
        if self.included_code:
            bits.append(f"{len(self.code_files)} file(s) of source attached")
        else:
            bits.append("no source attached")
        if self.kb_titles:
            bits.append(f"{len(self.kb_titles)} KB entr(y/ies)")
        if self.truncated:
            bits.append("TRUNCATED to fit the 2000-char limit")
        return ", ".join(bits)


def build_prompt(
    finding: Finding,
    matches: list[CodeMatch] | None = None,
    kb_entries: list[dict[str, Any]] | None = None,
    repo_root: Path | None = None,
    include_code: bool = False,
    max_context_lines: int = 120,
    question: str = "",
) -> RemediationRequest:
    """Assemble the remediation prompt.

    Sections are added in priority order and the whole thing is truncated to
    the endpoint's 2000-character limit, so the finding itself always survives
    and the code context is what gets cut.
    """
    matches = matches or []
    kb_entries = kb_entries or []

    head: list[str] = [
        "I need to fix a security finding from my Lorikeet engagement.",
        "",
        f"Finding #{finding.id}: {finding.title}",
        f"Severity: {finding.severity.upper()}"
        + (f" (CVSS {finding.cvss_score})" if finding.cvss_score else ""),
    ]
    if finding.cwe_id:
        head.append(f"CWE: {finding.cwe_id}")
    if finding.affected_asset:
        head.append(f"Affected: {finding.affected_asset}")
    if finding.description:
        head.append(f"\nDescription: {_clip(finding.description, 500)}")
    if finding.evidence:
        head.append(f"\nEvidence: {_clip(_redact(finding.evidence), 400)}")

    tail: list[str] = [
        "",
        question.strip()
        or (
            "Give me the concrete code-level fix: what to change, why that "
            "closes it, and how to verify it is actually closed. Be specific "
            "and skip the general advice."
        ),
    ]

    code_section: list[str] = []
    code_files: list[str] = []
    if include_code and matches and repo_root is not None:
        snippet = snippet_for_prompt(matches, repo_root, max_lines=max_context_lines)
        if snippet:
            code_section = ["", "Local code that may be responsible:", _redact(snippet)]
            code_files = _unique_files(matches, repo_root)

    kb_section: list[str] = []
    kb_titles: list[str] = []
    if kb_entries:
        lines = []
        for entry in kb_entries[:3]:
            title = str(entry.get("title") or entry.get("name") or "").strip()
            if not title:
                continue
            kb_titles.append(title)
            source = str(entry.get("source") or "").strip()
            lines.append(f"- {title}" + (f" ({source})" if source else ""))
        if lines:
            kb_section = ["", "Relevant knowledge base entries:", *lines]

    prompt, truncated = _assemble(head, kb_section, code_section, tail)

    return RemediationRequest(
        finding=finding,
        prompt=prompt,
        included_code=bool(code_section) and not truncated,
        code_files=code_files,
        kb_titles=kb_titles,
        truncated=truncated,
    )


def kb_query(finding: Finding) -> str:
    """The best knowledge-base query for a finding."""
    parts = [finding.title]
    if finding.cwe_id:
        parts.append(finding.cwe_id)
    elif finding.category:
        parts.append(finding.category)
    return " ".join(p for p in parts if p)[:200]


def verification_prompt(finding: Finding, what_changed: str) -> str:
    """Ask Lory whether a described change actually closes the finding."""
    return _clip(
        "\n".join(
            [
                f"I changed code to fix finding #{finding.id} ({finding.title}, "
                f"{finding.severity}).",
                "",
                f"What I changed: {what_changed.strip()}",
                "",
                "Does that actually close the finding? Tell me what is still "
                "exploitable, what I should test to confirm, and whether this "
                "is ready for a retest request.",
            ]
        ),
        MAX_PROMPT_CHARS,
    )


# ── helpers ─────────────────────────────────────────────────────────────────


def _assemble(*sections: list[str]) -> tuple[str, bool]:
    """Join sections, dropping the optional middle ones if over budget."""
    head, kb, code, tail = sections
    full = "\n".join([*head, *kb, *code, *tail]).strip()
    if len(full) <= MAX_PROMPT_CHARS:
        return full, False

    without_code = "\n".join([*head, *kb, *tail]).strip()
    if len(without_code) <= MAX_PROMPT_CHARS:
        return without_code, True

    without_kb = "\n".join([*head, *tail]).strip()
    if len(without_kb) <= MAX_PROMPT_CHARS:
        return without_kb, True

    return _clip(without_kb, MAX_PROMPT_CHARS), True


def _clip(text: str, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _redact(text: str) -> str:
    """Mask anything that looks like a live secret before it goes over the wire.

    Best-effort. It reduces accidental disclosure; it is not a guarantee, and
    the README says so.
    """
    out = text or ""
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: _mask(m.group(0)), out)
    return out


def _mask(value: str) -> str:
    if "=" in value or ":" in value:
        separator = "=" if "=" in value else ":"
        key, _, _ = value.partition(separator)
        return f"{key}{separator} [REDACTED]"
    return "[REDACTED]"


def _unique_files(matches: list[CodeMatch], root: Path) -> list[str]:
    seen: list[str] = []
    for match in matches:
        try:
            rel = str(match.path.relative_to(root))
        except ValueError:
            rel = str(match.path)
        if rel not in seen:
            seen.append(rel)
    return seen
