"""Client for the Lorikeet portal's PHP endpoints.

MCP is the tenant-scoped, token-authenticated surface — good for CI, capped at
50 rows, and bodies only via ``findings.get``. The portal's own AJAX endpoints
are richer, and this client uses them when a dashboard session cookie is
available:

==================================================  ====================================
endpoint                                            what it gives you
==================================================  ====================================
``/ptaas/dashboard/ajax/findings-export.php``       up to 5000 findings with full
                                                    bodies, in JSON, CSV, or SARIF
``/ptaas/dashboard/ajax/attestation.php``           the attestation letter for an
                                                    engagement, HTML or JSON
``/ptaas/dashboard/ajax/lory-findings-review.php``  the AI review queue (staff tokens
                                                    only; clients get 403)
==================================================  ====================================

All of them authenticate by ``PHPSESSID`` and scope every query to the session's
``company_id``. Findings the AI produced that have not passed human review are
never returned — the export applies the same ``review_state`` gate the portal
reads through, so this client cannot see unreviewed findings even accidentally.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from lory_code_security.core.config import Config
from lory_code_security.core.errors import AuthError, ProtocolError, TransportError

EXPORT_PATH = "/ptaas/dashboard/ajax/findings-export.php"
ATTESTATION_PATH = "/ptaas/dashboard/ajax/attestation.php"
REVIEW_PATH = "/ptaas/dashboard/ajax/lory-findings-review.php"

EXPORT_FORMATS = ("json", "csv", "sarif")
#: ``all`` covers both; ``ai`` is what Lory's engine produced, ``pentest`` is
#: everything else on that store (manual testing and older imports).
FINDING_SOURCES = ("all", "ai", "pentest")


@dataclass
class ExportResult:
    findings: list[dict[str, Any]]
    generated_at: str = ""
    company: str = ""
    count: int = 0
    raw: str = ""


class PortalClient:
    """Session-cookie client for the portal's PHP APIs."""

    def __init__(self, cfg: Config) -> None:
        if not cfg.session_cookie:
            raise AuthError(
                "the portal APIs need a dashboard session cookie. Log into the "
                "portal, copy the PHPSESSID cookie, and set session_cookie in "
                "config.yml (or LORY_SESSION_COOKIE)."
            )
        self.cfg = cfg
        self.base_url = cfg.base_url.rstrip("/")

    # ── plumbing ────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        from lory_code_security import __version__

        return {
            "Cookie": f"{self.cfg.session_cookie_name}={self.cfg.session_cookie}",
            "Accept": "application/json, application/sarif+json, text/csv, text/html",
            "User-Agent": f"lory-code-security/{__version__}",
        }

    def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        url = self.base_url + path
        try:
            with httpx.Client(timeout=self.cfg.timeout, verify=self.cfg.verify_tls,
                              follow_redirects=False) as client:
                resp = client.get(url, headers=self._headers(), params=params or {})
        except httpx.HTTPError as exc:
            raise TransportError(f"{url}: {exc}") from exc

        if resp.status_code in (301, 302, 303, 307, 308):
            # The portal bounces unauthenticated requests to the login page
            # rather than returning 401, so a redirect means a dead session.
            raise AuthError(
                f"{path} redirected to {resp.headers.get('location', 'the login page')} "
                "— the session cookie has expired. Copy a fresh PHPSESSID from the portal."
            )
        if resp.status_code == 401:
            raise AuthError(f"{path}: the portal rejected the session cookie")
        if resp.status_code == 403:
            raise AuthError(f"{path}: this endpoint is staff-only for your account")
        if resp.status_code >= 500:
            raise TransportError(f"{path} returned HTTP {resp.status_code}")
        if resp.status_code >= 400:
            raise ProtocolError(f"{path} returned HTTP {resp.status_code}")

        return resp

    # ── findings ────────────────────────────────────────────────────────────

    def export_findings(
        self,
        source: str = "all",
        severity: list[str] | None = None,
        status: str | None = None,
    ) -> ExportResult:
        """Pull findings with full bodies from ``findings-export.php``.

        This is the preferred read path when a session cookie is present:
        MCP's ``findings.list`` caps at 50 rows and omits description,
        evidence, and remediation.
        """
        params: dict[str, Any] = {"format": "json", "source": _source(source)}
        if severity:
            params["severity"] = ",".join(s.lower() for s in severity)
        if status:
            params["status"] = status.lower()

        resp = self._get(EXPORT_PATH, params)
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(
                f"{EXPORT_PATH} did not return JSON: {resp.text[:200]!r}"
            ) from exc

        if isinstance(data, dict) and data.get("success") is False:
            raise ProtocolError(str(data.get("error") or "export failed"))
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            raise ProtocolError(f"{EXPORT_PATH} returned an unexpected shape: {list(data)}")

        return ExportResult(
            findings=[f for f in data["findings"] if isinstance(f, dict)],
            generated_at=str(data.get("generated_at", "")),
            company=str(data.get("company", "")),
            count=int(data.get("count") or 0),
            raw=resp.text,
        )

    def export_raw(
        self,
        fmt: str = "sarif",
        source: str = "all",
        severity: list[str] | None = None,
        status: str | None = None,
    ) -> str:
        """Fetch an export verbatim. ``sarif`` is the one CI wants.

        SARIF drops straight into GitHub code scanning and Defender, which is
        the cheapest way to get engagement findings in front of developers.
        """
        fmt = fmt.lower()
        if fmt not in EXPORT_FORMATS:
            raise ProtocolError(f"format must be one of: {', '.join(EXPORT_FORMATS)}")

        params: dict[str, Any] = {"format": fmt, "source": _source(source)}
        if severity:
            params["severity"] = ",".join(s.lower() for s in severity)
        if status:
            params["status"] = status.lower()

        return self._get(EXPORT_PATH, params).text

    # ── engagement deliverables ─────────────────────────────────────────────

    def attestation(
        self, engagement_id: int, engagement_type: str = "ai", fmt: str = "json"
    ) -> str:
        """Fetch the attestation letter for one engagement.

        ``html`` is print-ready (the portal's delivery path is print-to-PDF);
        ``json`` is the structured version.
        """
        resp = self._get(
            ATTESTATION_PATH,
            {
                "engagement": int(engagement_id),
                "type": "pentest" if engagement_type == "pentest" else "ai",
                "format": "html" if fmt == "html" else "json",
            },
        )
        return resp.text

    # ── AI review queue (staff) ─────────────────────────────────────────────

    def review_queue(
        self, engagement_id: int | None = None, state: str = "pending_review"
    ) -> list[dict[str, Any]]:
        """List AI findings awaiting human review.

        Staff-only upstream. Client accounts get a 403, surfaced as
        :class:`AuthError` rather than an empty list, so nobody mistakes a
        permission problem for an empty queue.
        """
        params: dict[str, Any] = {"action": "list", "state": state}
        if engagement_id:
            params["engagement"] = int(engagement_id)

        resp = self._get(REVIEW_PATH, params)
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"{REVIEW_PATH} did not return JSON") from exc

        if isinstance(data, dict) and data.get("success") is False:
            raise ProtocolError(str(data.get("error") or "review list failed"))
        rows = data.get("findings") if isinstance(data, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    def probe(self) -> dict[str, Any]:
        """Cheap check that the session cookie is live, for ``lory doctor``."""
        try:
            result = self.export_findings()
        except AuthError as exc:
            return {"ok": False, "reason": str(exc)}
        except (TransportError, ProtocolError) as exc:
            return {"ok": False, "reason": str(exc)}
        return {"ok": True, "count": result.count, "company": result.company}


def _source(source: str) -> str:
    source = (source or "all").lower()
    return source if source in FINDING_SOURCES else "all"
