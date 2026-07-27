"""Lory's structured-block response contract.

Every conversational Lory surface that loads ``response-format-blocks.md``
answers with a single JSON object::

    {"blocks": [ {...}, ... ], "suggestions": ["...", ...]}

This module is the Python-side mirror of that skill file. It exists so the TUI
can render blocks and — more importantly — so the harness can assert that the
contract still holds after someone hot-edits a skill in the admin console.
Keep :data:`BLOCK_SPECS` in step with ``ptaas/ai/skills/response-format-blocks.md``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

#: block type -> (required keys, optional keys)
BLOCK_SPECS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "text":    (("content",), ()),
    "list":    (("items",), ()),
    "pricing": (("service", "price"), ("timeline", "description")),
    "link":    (("url", "title"), ("description",)),
    "cta":     (("label", "url"), ()),
    "table":   (("headers", "rows"), ()),
    "chart":   (("chart_type", "labels", "data"), ("title", "colors")),
    "report":  (("title", "sections"), ("generated",)),
    "invoice": (("service", "price"), ("service_type", "tier", "description")),
    "booking": ((), ("context",)),
    "handoff": ((), ("context",)),
}

BLOCK_TYPES = tuple(BLOCK_SPECS)

#: Blocks that move money or a human. The TUI highlights these; the harness
#: refuses to let a scenario emit them by accident.
TRANSACTIONAL_BLOCKS = frozenset({"invoice", "booking", "handoff"})

CHART_TYPES = ("doughnut", "bar", "horizontalBar", "pie")

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
_EM_DASH_RE = re.compile(r"[–—]")


@dataclass
class Block:
    """One rendered unit of a Lory reply."""

    type: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def is_known(self) -> bool:
        return self.type in BLOCK_SPECS

    @property
    def is_transactional(self) -> bool:
        return self.type in TRANSACTIONAL_BLOCKS

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, **self.data}

    def text_content(self) -> str:
        """Everything in this block that a `contains` assertion should see."""
        parts: list[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, dict):
                for v in value.values():
                    walk(v)
            elif isinstance(value, (list, tuple)):
                for v in value:
                    walk(v)
            elif value is not None:
                parts.append(str(value))

        walk(self.data)
        return "\n".join(parts)


def strip_code_fences(raw: str) -> str:
    """Remove a ``` wrapper the model was told never to emit.

    ``response-format-blocks.md`` forbids fences outright, so the harness checks
    for them separately — but the TUI still has to render a fenced reply rather
    than showing the user a parse error.
    """
    text = raw.strip()
    if text.startswith("```"):
        text = _FENCE_RE.sub("", text)
    return text.strip()


def has_code_fence(raw: str) -> bool:
    return "```" in (raw or "")


def has_em_dash(raw: str) -> bool:
    """True if an en/em dash is present. The skill file bans both."""
    return bool(_EM_DASH_RE.search(raw or ""))


def parse_blocks(payload: Any) -> list[Block]:
    """Coerce a ``blocks`` payload into :class:`Block` objects.

    Accepts the list itself, the enclosing ``{"blocks": [...]}`` object, or a
    raw JSON string (fenced or not). Entries that are not objects are dropped;
    an entry with no ``type`` becomes a ``text`` block so nothing is silently
    lost from the transcript.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(strip_code_fences(payload))
        except (json.JSONDecodeError, ValueError):
            return [Block("text", {"content": payload})]

    if isinstance(payload, dict):
        payload = payload.get("blocks", [])

    if not isinstance(payload, list):
        return []

    blocks: list[Block] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        data = {k: v for k, v in entry.items() if k != "type"}
        blocks.append(Block(str(entry.get("type") or "text"), data))
    return blocks


def validate_block(block: Block) -> list[str]:
    """Structural problems with a single block, as human-readable strings."""
    problems: list[str] = []

    if not block.is_known:
        return [f"unknown block type {block.type!r}"]

    required, optional = BLOCK_SPECS[block.type]
    for key in required:
        if key not in block.data:
            problems.append(f"{block.type}: missing required key {key!r}")

    allowed = set(required) | set(optional)
    for key in block.data:
        if key not in allowed:
            problems.append(f"{block.type}: unexpected key {key!r}")

    if block.type == "list" and not isinstance(block.get("items"), list):
        problems.append("list: 'items' must be an array")

    if block.type == "table":
        headers, rows = block.get("headers"), block.get("rows")
        if not isinstance(headers, list):
            problems.append("table: 'headers' must be an array")
        if not isinstance(rows, list):
            problems.append("table: 'rows' must be an array")
        elif isinstance(headers, list):
            for i, row in enumerate(rows):
                if not isinstance(row, list):
                    problems.append(f"table: row {i} must be an array")
                elif len(row) != len(headers):
                    problems.append(
                        f"table: row {i} has {len(row)} cells, headers has {len(headers)}"
                    )

    if block.type == "chart":
        chart_type = block.get("chart_type")
        if chart_type not in CHART_TYPES:
            problems.append(
                f"chart: chart_type {chart_type!r} not in {', '.join(CHART_TYPES)}"
            )
        labels, data = block.get("labels"), block.get("data")
        if not isinstance(labels, list) or not isinstance(data, list):
            problems.append("chart: 'labels' and 'data' must both be arrays")
        elif len(labels) != len(data):
            problems.append(
                f"chart: {len(labels)} labels but {len(data)} data points"
            )

    if block.type == "report":
        sections = block.get("sections")
        if not isinstance(sections, list):
            problems.append("report: 'sections' must be an array")
        else:
            for i, section in enumerate(sections):
                if not isinstance(section, dict) or "heading" not in section:
                    problems.append(f"report: section {i} needs a 'heading'")

    return problems


def validate_reply(blocks: list[Block], suggestions: list[str]) -> list[str]:
    """Whole-reply contract checks, beyond per-block structure."""
    problems: list[str] = []
    for block in blocks:
        problems.extend(validate_block(block))

    cta_count = sum(1 for b in blocks if b.type == "cta")
    if cta_count > 1:
        problems.append(f"{cta_count} cta blocks; the contract allows at most one")
    if cta_count == 1 and blocks and blocks[-1].type != "cta":
        problems.append("the cta block must be last")

    if suggestions:
        if not 2 <= len(suggestions) <= 4:
            problems.append(
                f"{len(suggestions)} suggestions; the contract requires 2 to 4"
            )
        for s in suggestions:
            if len(s) > 35:
                problems.append(f"suggestion over 35 chars: {s!r}")

    return problems
