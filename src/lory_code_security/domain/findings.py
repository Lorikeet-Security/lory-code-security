"""Finding model, retrieval, and local triage state.

Findings come from the Lorikeet Security platform over MCP (``findings.list``
and ``findings.get``). The platform owns the authoritative record; this module
holds a local read model plus the bits of workflow that belong on the
developer's machine — which findings you have looked at, which you have marked
as fixed locally, and which files you associated with each one.

Local triage state is deliberately separate from the platform's ``status``
field. Marking something fixed here does not close it upstream; only a
retest request (``retest.request``) does that, and it is a human decision.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lory_code_security.client.mcp import McpClient
from lory_code_security.core.errors import LoryConsoleError, ToolError

if TYPE_CHECKING:
    from lory_code_security.client.portal import PortalClient

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

#: Local-only workflow states. See the module docstring on why these do not
#: mirror the platform's ``status`` enum.
TRIAGE_STATES = ("new", "reading", "fixing", "fixed", "wontfix")


@dataclass
class Finding:
    """One platform finding, normalised."""

    id: int
    title: str = ""
    severity: str = "info"
    status: str = ""
    affected_asset: str = ""
    category: str = ""
    cwe_id: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    project_id: int | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    discovered_at: str = ""
    #: Provenance, present on the portal export: which engine found this, in
    #: which engagement, on which attack vector.
    source: str = ""
    engagement_id: int | None = None
    vector: str = ""
    #: Everything the read path returned, so nothing is lost to normalisation.
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def found_by_ai(self) -> bool:
        return self.source.lower() in ("lory_ai", "mcp", "lory_v2")

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.lower(), len(SEVERITY_ORDER))

    @property
    def label(self) -> str:
        return f"#{self.id} {self.title}"

    @property
    def is_detailed(self) -> bool:
        """True once ``findings.get`` has filled in the body."""
        return bool(self.description or self.evidence)

    def summary(self) -> str:
        parts = [f"#{self.id}", self.severity.upper(), self.title]
        if self.affected_asset:
            parts.append(f"on {self.affected_asset}")
        return " ".join(p for p in parts if p)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "affected_asset": self.affected_asset,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "project_id": self.project_id,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at,
            "source": self.source,
            "engagement_id": self.engagement_id,
            "vector": self.vector,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Finding:
        """Build a Finding from either read path.

        MCP's ``findings.list`` returns flat columns; the portal's
        ``findings-export.php`` nests CVSS and provenance. Flatten both here so
        nothing downstream has to know which source it came from.
        """
        row = dict(row)

        cvss_block = row.get("cvss")
        if isinstance(cvss_block, dict):
            row.setdefault("cvss_score", cvss_block.get("score"))
            row.setdefault("cvss_vector", cvss_block.get("vector"))

        provenance = row.get("provenance")
        if isinstance(provenance, dict):
            row.setdefault("source", provenance.get("source"))
            row.setdefault("engagement_id", provenance.get("engagement"))
            row.setdefault("vector", provenance.get("vector"))

        def text(*keys: str) -> str:
            for key in keys:
                value = row.get(key)
                if value not in (None, ""):
                    return str(value)
            return ""

        score = row.get("cvss_score")
        try:
            cvss = float(score) if score not in (None, "") else None
        except (TypeError, ValueError):
            cvss = None

        return cls(
            id=int(row.get("id") or 0),
            title=text("title", "name"),
            severity=text("severity").lower() or "info",
            status=text("status"),
            affected_asset=text("affected_asset", "asset", "target"),
            category=text("category", "type"),
            cwe_id=text("cwe_id", "cwe"),
            cvss_score=cvss,
            cvss_vector=text("cvss_vector"),
            project_id=int(row["project_id"]) if str(row.get("project_id", "")).isdigit() else None,
            description=text("description", "summary"),
            evidence=text("evidence", "proof", "reproduction"),
            remediation=text("remediation", "recommendation", "fix"),
            discovered_at=text("discovered_at", "created_at", "found_at"),
            source=text("source") or "manual",
            engagement_id=(
                int(row["engagement_id"]) if str(row.get("engagement_id", "")).isdigit() else None
            ),
            vector=text("vector"),
            raw=dict(row),
        )


class FindingStore:
    """Reads findings from the platform and caches them on disk.

    Two read paths, in preference order:

    1. **Portal export** (``findings-export.php``, session cookie) — up to 5000
       findings with description, evidence, remediation, CVSS, and provenance
       in one request.
    2. **MCP** (``findings.list``, bearer token) — tenant-scoped and
       CI-friendly, but capped at 50 rows with no bodies until you call
       ``findings.get`` per finding.

    Nothing here discovers vulnerabilities. Findings are produced by Lory's
    engine and by Lorikeet's testers, reviewed by a human, and read here.

    The cache exists so the TUI opens instantly and so `lory findings --cached`
    works offline. It is never a source of truth: anything that acts on a
    finding re-reads it from the platform first.
    """

    def __init__(
        self,
        client: McpClient | None,
        portal: PortalClient | None = None,
        cache_path: Path | None = None,
    ) -> None:
        self.client = client
        self.portal = portal
        self.cache_path = cache_path
        self._by_id: dict[int, Finding] = {}
        #: Which path last served a fetch, for the UI to show.
        self.last_source: str = "none"

    # ── retrieval ───────────────────────────────────────────────────────────

    def fetch(
        self,
        severity: str | None = None,
        status: str | None = None,
        project_id: int | None = None,
        affected_asset: str | None = None,
        limit: int = 50,
        prefer: str = "auto",
    ) -> list[Finding]:
        """Pull findings from the platform and refresh the cache.

        ``prefer`` is ``auto`` (portal when available), ``portal``, or ``mcp``.
        """
        if prefer in ("auto", "portal") and self.portal is not None:
            try:
                return self._fetch_portal(severity, status, affected_asset)
            except LoryConsoleError:
                if prefer == "portal":
                    raise
                # Fall through to MCP: an expired cookie should degrade to the
                # narrower path rather than failing the command outright.

        return self._fetch_mcp(severity, status, project_id, affected_asset, limit)

    def _fetch_portal(
        self, severity: str | None, status: str | None, affected_asset: str | None
    ) -> list[Finding]:
        assert self.portal is not None
        result = self.portal.export_findings(
            severity=[severity] if severity else None, status=status
        )
        findings = [Finding.from_row(row) for row in result.findings]
        if affected_asset:
            needle = affected_asset.lower()
            findings = [f for f in findings if needle in f.affected_asset.lower()]

        for finding in findings:
            self._by_id[finding.id] = finding

        self.last_source = "portal"
        self.save_cache()
        return sort_findings(findings)

    def _fetch_mcp(
        self,
        severity: str | None,
        status: str | None,
        project_id: int | None,
        affected_asset: str | None,
        limit: int,
    ) -> list[Finding]:
        if self.client is None:
            raise ToolError(
                "no read path available: set session_cookie for the portal export, "
                "or mcp_token for MCP"
            )

        args: dict[str, Any] = {"limit": max(1, min(50, limit))}
        if severity:
            args["severity"] = severity.lower()
        if status:
            args["status"] = status.lower().replace(" ", "_")
        if project_id is not None:
            args["project_id"] = project_id
        if affected_asset:
            args["affected_asset"] = affected_asset

        result = self.client.call_tool("findings.list", args)
        findings = [Finding.from_row(row) for row in result.rows()]
        for finding in findings:
            existing = self._by_id.get(finding.id)
            # findings.list returns no body; keep a detail fetch we already have.
            if existing and existing.is_detailed and not finding.is_detailed:
                finding.description = existing.description
                finding.evidence = existing.evidence
                finding.remediation = existing.remediation
            self._by_id[finding.id] = finding

        self.last_source = "mcp"
        self.save_cache()
        return sort_findings(findings)

    def detail(self, finding_id: int, refresh: bool = False) -> Finding:
        """Fetch the full body of one finding via ``findings.get``."""
        cached = self._by_id.get(finding_id)
        if cached is not None and cached.is_detailed and not refresh:
            return cached

        if self.client is None:
            if cached is not None:
                return cached
            raise ToolError(f"finding #{finding_id} is not cached and MCP is unavailable")

        result = self.client.call_tool("findings.get", {"id": finding_id})
        data = result.structured
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            raise ToolError(f"findings.get returned an unexpected shape for #{finding_id}")

        finding = Finding.from_row(data)
        self._by_id[finding.id] = finding
        self.save_cache()
        return finding

    def request_retest(self, finding_id: int, note: str = "") -> dict[str, Any]:
        """Ask the Lorikeet team to re-test a finding you believe is fixed."""
        if self.client is None:
            raise ToolError("retest requests require an MCP token")
        args: dict[str, Any] = {"finding_id": finding_id}
        if note:
            args["note"] = note[:2000]
        result = self.client.call_tool("retest.request", args)
        return result.structured if isinstance(result.structured, dict) else {"raw": result.text}

    def search_kb(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        """Look the finding class up in the vulnerability knowledge base."""
        if self.client is None:
            return []
        try:
            result = self.client.call_tool(
                "kb.search", {"q": query[:200], "limit": max(1, min(25, limit))}
            )
        except ToolError:
            # kb:read is a separate scope; a token without it should not break
            # the remediation flow, just make it thinner.
            return []
        return result.rows()

    # ── cache ───────────────────────────────────────────────────────────────

    def all(self) -> list[Finding]:
        return sort_findings(self._by_id.values())

    def get(self, finding_id: int) -> Finding | None:
        return self._by_id.get(finding_id)

    def load_cache(self) -> list[Finding]:
        if not self.cache_path or not self.cache_path.exists():
            return []
        try:
            data = json.loads(self.cache_path.read_text())
        except (OSError, json.JSONDecodeError, ValueError):
            return []
        rows = data.get("findings", []) if isinstance(data, dict) else data
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                finding = Finding.from_row(row)
                self._by_id.setdefault(finding.id, finding)
        return self.all()

    def save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(
                    {
                        "fetched_at": datetime.now(UTC).isoformat(),
                        "findings": [f.to_dict() for f in self.all()],
                    },
                    indent=2,
                )
            )
        except OSError:
            pass  # a cache that cannot be written is not worth failing a run over


class TriageLog:
    """Local, developer-side workflow state. One JSON file, human-editable."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError, ValueError):
            return
        if isinstance(data, dict):
            self.entries = {str(k): v for k, v in data.items() if isinstance(v, dict)}

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True))
        except OSError:
            pass

    def state(self, finding_id: int) -> str:
        return str(self.entries.get(str(finding_id), {}).get("state", "new"))

    def note(self, finding_id: int) -> str:
        return str(self.entries.get(str(finding_id), {}).get("note", ""))

    def files(self, finding_id: int) -> list[str]:
        raw = self.entries.get(str(finding_id), {}).get("files", [])
        return [str(f) for f in raw] if isinstance(raw, list) else []

    def set_state(self, finding_id: int, state: str, note: str = "") -> None:
        if state not in TRIAGE_STATES:
            raise ValueError(f"state must be one of: {', '.join(TRIAGE_STATES)}")
        entry = self.entries.setdefault(str(finding_id), {})
        entry["state"] = state
        entry["updated_at"] = datetime.now(UTC).isoformat()
        if note:
            entry["note"] = note
        self.save()

    def link_files(self, finding_id: int, paths: Iterable[str]) -> None:
        entry = self.entries.setdefault(str(finding_id), {})
        existing = set(entry.get("files") or [])
        entry["files"] = sorted(existing | {str(p) for p in paths})
        self.save()


# ── helpers ─────────────────────────────────────────────────────────────────


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Severity first (critical → info), then highest CVSS, then newest id."""
    return sorted(findings, key=lambda f: (f.rank, -(f.cvss_score or 0.0), -f.id))


def filter_findings(
    findings: Iterable[Finding],
    query: str = "",
    severity: str | None = None,
    status: str | None = None,
) -> list[Finding]:
    """Free-text and field filtering, applied client-side."""
    needle = query.strip().lower()
    out: list[Finding] = []
    for finding in findings:
        if severity and finding.severity.lower() != severity.lower():
            continue
        if status and status.lower() not in finding.status.lower():
            continue
        if needle:
            haystack = " ".join(
                (finding.title, finding.affected_asset, finding.category,
                 finding.cwe_id, finding.description, str(finding.id))
            ).lower()
            if needle not in haystack:
                continue
        out.append(finding)
    return sort_findings(out)


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.lower()] = counts.get(finding.severity.lower(), 0) + 1
    return counts


def cwe_number(cwe_id: str) -> str:
    """``CWE-89`` → ``89``. Returns '' when there is no usable id."""
    match = re.search(r"(\d+)", cwe_id or "")
    return match.group(1) if match else ""
