"""Map a platform finding onto local source.

A finding says "reflected XSS in the `q` parameter of /search on
app.example.com". The developer's question is "which file". This module closes
that gap heuristically: it pulls searchable tokens out of the finding
(parameters, paths, headers, cookie names, plus CWE-specific sink patterns) and
greps the working tree for them.

This is a *lead generator*, not an analyser. It ranks candidates and shows the
lines; a human decides. Everything it returns is labelled with the token that
produced the hit, so a bad lead is obvious rather than authoritative.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from lory_code_security.domain.findings import Finding, cwe_number

#: Sink patterns worth grepping for, per CWE. Deliberately small: a pattern
#: that fires on every file is worse than no pattern at all.
CWE_PATTERNS: dict[str, tuple[str, ...]] = {
    "79":  (r"innerHTML", r"dangerouslySetInnerHTML", r"v-html", r"\|\s*safe\b",
            r"echo\s+\$_"),
    "89":  (r"SELECT .*\+", r"execute\(.*%", r"\.raw\(", r"query\(\s*[\"'].*\$", r"f[\"']SELECT"),
    "78":  (r"os\.system", r"subprocess\.\w+\(.*shell\s*=\s*True", r"exec\(",
            r"shell_exec", r"passthru"),
    "22":  (r"open\(.*\+", r"\.\./", r"path\.join\(.*req\.", r"file_get_contents\(\$"),
    "352": (r"csrf", r"SameSite", r"verify_token"),
    "287": (r"login", r"authenticate", r"session_start", r"jwt", r"verify\("),
    "639": (r"findById", r"where\(\s*[\"']id", r"params\[[\"']id", r"get_object_or_404"),
    "502": (r"pickle\.loads", r"yaml\.load\(", r"unserialize\(", r"ObjectInputStream"),
    "798": (r"api[_-]?key\s*=", r"secret\s*=", r"password\s*=", r"token\s*="),
    "918": (r"requests\.get\(.*\+", r"curl_exec", r"fetch\(.*req\.", r"urlopen\("),
    "1004": (r"httponly", r"set_cookie", r"setcookie"),
    "614": (r"secure\s*[:=]", r"set_cookie", r"setcookie"),
}

#: Never worth grepping — every codebase has thousands of them.
_STOP_TOKENS = frozenset({
    "id", "url", "get", "post", "http", "https", "www", "com", "net", "org",
    "api", "app", "web", "the", "and", "for", "src", "lib", "dev", "test",
    "user", "name", "type", "data", "page", "site", "html", "json", "php",
})

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv",
    "venv", ".tox", ".mypy_cache", ".pytest_cache", "target", ".next", "out",
    "coverage", ".idea", ".vscode",
})

_TEXT_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java", ".cs",
    ".kt", ".swift", ".rs", ".c", ".h", ".cpp", ".hpp", ".scala", ".ex", ".exs",
    ".pl", ".sh", ".bash", ".sql", ".html", ".htm", ".vue", ".svelte", ".erb",
    ".twig", ".blade", ".jinja", ".j2", ".yaml", ".yml", ".json", ".toml",
    ".conf", ".ini", ".env", ".tf", ".gradle", ".xml",
})

_MAX_FILE_BYTES = 1_000_000


@dataclass
class CodeMatch:
    path: Path
    line: int
    text: str
    #: The search token that produced this hit, so a false lead is visible.
    token: str
    score: float = 0.0

    def display(self, root: Path) -> str:
        try:
            rel = self.path.relative_to(root)
        except ValueError:
            rel = self.path
        return f"{rel}:{self.line}"


@dataclass
class SearchPlan:
    """The tokens derived from a finding, in the order they will be tried."""

    literals: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.literals and not self.patterns


def build_plan(finding: Finding) -> SearchPlan:
    """Derive search tokens from a finding's text.

    Ordered most- to least-specific: explicit file paths beat URL paths, which
    beat parameter names, which beat generic CWE sink patterns.
    """
    blob = " ".join(
        (finding.title, finding.affected_asset, finding.description,
         finding.evidence, finding.remediation)
    )

    literals: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        token = token.strip().strip(".,;:'\"()[]{}")
        if len(token) < 3 or token.lower() in _STOP_TOKENS:
            return
        if token.lower() in seen:
            return
        seen.add(token.lower())
        literals.append(token)

    # 1. Source paths named outright in the evidence — the strongest signal.
    for match in re.finditer(r"\b[\w./-]+\.(?:py|js|jsx|ts|tsx|php|rb|go|java|cs|rs|vue)\b", blob):
        add(match.group(0))

    # 2. Query/body parameter names. Findings name these both ways round —
    #    "the parameter `q`" and "the `q` parameter" — so match both.
    for match in re.finditer(r"[?&]([A-Za-z_][\w-]{2,})=", blob):
        add(match.group(1))
    for match in re.finditer(
        r"\b(?:parameter|param|field|input|argument)s?\s+[`'\"]?([A-Za-z_][\w-]{2,})", blob, re.I
    ):
        add(match.group(1))
    for match in re.finditer(
        r"[`'\"]?\b([A-Za-z_][\w-]{2,})[`'\"]?\s+(?:parameter|param|field|input|argument)\b",
        blob, re.I,
    ):
        add(match.group(1))

    # 3. URL path segments — route names usually appear verbatim in the router.
    for match in re.finditer(r"https?://[^\s\"'<>]+", blob):
        for segment in re.split(r"[/?#]", match.group(0).split("://", 1)[-1])[1:]:
            if segment and not segment.replace(".", "").isdigit():
                add(segment)
    for match in re.finditer(r"(?<![\w:])/(?:[\w-]+/?){1,4}(?![\w.])", blob):
        for segment in match.group(0).strip("/").split("/"):
            add(segment)

    # 4. Header and cookie names.
    for match in re.finditer(r"\b((?:X-|Set-|Content-|Strict-)[A-Za-z-]{3,})\b", blob):
        add(match.group(1))

    patterns = list(CWE_PATTERNS.get(cwe_number(finding.cwe_id), ()))

    return SearchPlan(literals=literals[:12], patterns=patterns)


def locate(
    finding: Finding,
    root: Path,
    limit: int = 40,
    plan: SearchPlan | None = None,
) -> list[CodeMatch]:
    """Find local source that plausibly relates to ``finding``.

    Uses ``git grep`` inside a repo, then ``rg``, then a pure-Python walk, so
    it works with no external tools installed.
    """
    plan = plan or build_plan(finding)
    if plan.is_empty():
        return []

    matches: list[CodeMatch] = []
    for weight, token, is_regex in _weighted_tokens(plan):
        if len(matches) >= limit * 3:
            break
        for match in _grep(token, root, is_regex=is_regex, limit=limit):
            match.token = token
            match.score = weight * _path_weight(match.path)
            matches.append(match)

    return _dedupe(matches)[:limit]


def read_context(path: Path, line: int, before: int = 6, after: int = 6) -> list[tuple[int, str]]:
    """Read a window of source around ``line``, as ``(lineno, text)`` pairs."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []

    start = max(0, line - 1 - before)
    end = min(len(lines), line + after)
    return [(i + 1, lines[i]) for i in range(start, end)]


def snippet_for_prompt(
    matches: list[CodeMatch],
    root: Path,
    max_lines: int = 120,
    per_match: int = 5,
) -> str:
    """Render code context for a remediation prompt, within a line budget.

    Bounded on purpose: this text leaves the machine, so the size of what is
    sent must be predictable and small.
    """
    out: list[str] = []
    used = 0

    for match in matches:
        if used >= max_lines:
            break
        window = read_context(match.path, match.line, before=per_match // 2, after=per_match // 2)
        if not window:
            continue
        out.append(f"--- {match.display(root)} ---")
        used += 1
        for lineno, text in window:
            if used >= max_lines:
                break
            marker = ">" if lineno == match.line else " "
            out.append(f"{marker} {lineno:>5} | {text.rstrip()[:200]}")
            used += 1
        out.append("")
        used += 1

    return "\n".join(out).strip()


# ── search backends ─────────────────────────────────────────────────────────


def _weighted_tokens(plan: SearchPlan) -> list[tuple[float, str, bool]]:
    """Tokens paired with a relevance weight, most specific first."""
    tokens: list[tuple[float, str, bool]] = []
    for i, literal in enumerate(plan.literals):
        tokens.append((max(0.4, 1.0 - i * 0.05), literal, False))
    for pattern in plan.patterns:
        tokens.append((0.35, pattern, True))
    return tokens


def _grep(token: str, root: Path, is_regex: bool, limit: int) -> list[CodeMatch]:
    for backend in (_git_grep, _ripgrep, _python_grep):
        try:
            results = backend(token, root, is_regex, limit)
        except (OSError, subprocess.SubprocessError):
            continue
        if results is not None:
            return results
    return []


def _git_grep(token: str, root: Path, is_regex: bool, limit: int) -> list[CodeMatch] | None:
    if not shutil.which("git") or not (root / ".git").exists():
        return None
    cmd = ["git", "-C", str(root), "grep", "-n", "-I", "--no-color"]
    cmd.append("-E" if is_regex else "-F")
    cmd += ["-i", "-e", token]
    return _run_grep(cmd, root, limit)


def _ripgrep(token: str, root: Path, is_regex: bool, limit: int) -> list[CodeMatch] | None:
    if not shutil.which("rg"):
        return None
    cmd = ["rg", "--no-heading", "--line-number", "--color", "never", "-i", "--max-count", "5"]
    if not is_regex:
        cmd.append("--fixed-strings")
    cmd += ["-e", token, str(root)]
    return _run_grep(cmd, root, limit)


def _run_grep(cmd: list[str], root: Path, limit: int) -> list[CodeMatch]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    # 1 means "no matches" for both git grep and rg; anything higher is a real error.
    if proc.returncode > 1:
        return []

    matches: list[CodeMatch] = []
    for raw in proc.stdout.splitlines()[: limit * 2]:
        parts = raw.split(":", 2)
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        path = Path(parts[0])
        if not path.is_absolute():
            path = root / path
        if _skip(path):
            continue
        matches.append(
            CodeMatch(path=path, line=int(parts[1]), text=parts[2].strip()[:300], token="")
        )
        if len(matches) >= limit:
            break
    return matches


def _python_grep(token: str, root: Path, is_regex: bool, limit: int) -> list[CodeMatch]:
    """Fallback for machines with neither git nor ripgrep."""
    try:
        needle = re.compile(token if is_regex else re.escape(token), re.IGNORECASE)
    except re.error:
        return []

    matches: list[CodeMatch] = []
    for path in _walk(root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            with path.open(errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    if needle.search(line):
                        matches.append(
                            CodeMatch(path=path, line=lineno, text=line.strip()[:300], token="")
                        )
                        if len(matches) >= limit:
                            return matches
        except OSError:
            continue
    return matches


def _walk(root: Path):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS and not entry.is_symlink():
                    stack.append(entry)
            elif entry.suffix.lower() in _TEXT_SUFFIXES:
                yield entry


def _skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _path_weight(path: Path) -> float:
    """Prefer application source over tests, fixtures, and minified bundles."""
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if name.endswith((".min.js", ".map", ".lock")):
        return 0.2
    if parts & {"test", "tests", "spec", "specs", "fixtures", "__tests__", "examples"}:
        return 0.5
    if parts & {"src", "app", "lib", "api", "routes", "controllers", "handlers", "views"}:
        return 1.2
    return 1.0


def _dedupe(matches: list[CodeMatch]) -> list[CodeMatch]:
    """Highest-scoring hit per (file, line), then sorted by score."""
    best: dict[tuple[str, int], CodeMatch] = {}
    for match in matches:
        key = (str(match.path), match.line)
        if key not in best or match.score > best[key].score:
            best[key] = match
    return sorted(best.values(), key=lambda m: (-m.score, str(m.path), m.line))
