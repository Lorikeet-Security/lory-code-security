"""Client for Lory's chat endpoint.

``/ptaas/ajax/lory-public.php`` — no credential, IP rate limited.

The dashboard's own chat endpoint authenticates by PHP session and has no token
auth, so a bearer-token client cannot reach it. That is not a loss for this
tool: the remediation prompt carries the finding, its evidence, and its
knowledge base entries into the message, so the answer is grounded in the
finding regardless of which endpoint answers.

Request::

    {"message": "...", "history": [{"role": "user", "content": "..."}], "stream": true}

Non-streaming response is one of::

    {"success": true,  "blocks": [...], "suggestions": [...]}
    {"success": true,  "reply": "..."}                  # model broke the JSON contract
    {"success": false, "error": "..."}
    {"success": false, "paywall": true, "error": "...", "prompts_used": n, "prompts_limit": n}

Streaming response is SSE with three event names: ``block`` (one block object),
``done`` (``{"suggestions": [...]}``), and ``error``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from lory_code_security.core.config import Config
from lory_code_security.core.errors import AuthError, PaywallError, ProtocolError, TransportError
from lory_code_security.domain.blocks import Block, parse_blocks, validate_reply

_MAX_MESSAGE_CHARS = 2000  # both endpoints substr() to this
_MAX_HISTORY_CONTENT = 1000  # ...and to this, per history turn


@dataclass
class ChatReply:
    """One turn of Lory's side of the conversation."""

    blocks: list[Block] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    #: Set only when Lory ignored the JSON contract and replied in prose.
    plain_reply: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    #: Unparsed model output, when we have it. The fence/em-dash checks need
    #: the bytes as sent, not a re-serialisation.
    raw_text: str | None = None
    elapsed_ms: float = 0.0
    streamed: bool = False

    @property
    def block_types(self) -> list[str]:
        return [b.type for b in self.blocks]

    def text(self) -> str:
        """All prose in the reply, for substring assertions."""
        if self.plain_reply:
            return self.plain_reply
        return "\n".join(b.text_content() for b in self.blocks)

    def contract_problems(self) -> list[str]:
        """Structural violations of ``response-format-blocks.md``."""
        if self.plain_reply is not None and not self.blocks:
            return ["reply was prose, not the required {\"blocks\": [...]} object"]
        return validate_reply(self.blocks, self.suggestions)

    def to_history_turn(self) -> dict[str, str]:
        return {"role": "assistant", "content": self.text()[:_MAX_HISTORY_CONTENT]}


class ChatClient:
    """Talks to the chat endpoint. Holds no conversation state itself."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.url = cfg.chat_url()

    # ── plumbing ────────────────────────────────────────────────────────────

    def _headers(self, stream: bool) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json",
            "User-Agent": _user_agent(),
        }
        return headers

    def _payload(self, message: str, history: list[dict[str, str]], stream: bool) -> dict[str, Any]:
        trimmed = [
            {
                "role": "assistant" if turn.get("role") == "assistant" else "user",
                "content": str(turn.get("content", ""))[:_MAX_HISTORY_CONTENT],
            }
            for turn in history[-self.cfg.history_limit:]
        ]
        payload: dict[str, Any] = {
            "message": message[:_MAX_MESSAGE_CHARS],
            "history": trimmed,
        }
        if stream:
            payload["stream"] = True
        return payload

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.cfg.timeout, verify=self.cfg.verify_tls)

    # ── public API ──────────────────────────────────────────────────────────

    def send(
        self,
        message: str,
        history: list[dict[str, str]] | None = None,
        stream: bool | None = None,
    ) -> ChatReply:
        """Send one turn and return the complete reply."""
        stream = self.cfg.stream if stream is None else stream
        if stream:
            reply: ChatReply | None = None
            for event in self.stream(message, history):
                if isinstance(event, ChatReply):
                    reply = event
            if reply is None:  # pragma: no cover - stream() always yields a final reply
                raise ProtocolError("stream ended without a terminal event")
            return reply
        return self._send_blocking(message, history)

    def _send_blocking(
        self, message: str, history: list[dict[str, str]] | None
    ) -> ChatReply:
        started = time.perf_counter()
        try:
            with self._client() as client:
                resp = client.post(
                    self.url,
                    headers=self._headers(stream=False),
                    json=self._payload(message, history or [], stream=False),
                )
        except httpx.HTTPError as exc:
            raise TransportError(f"{self.url}: {exc}") from exc

        elapsed = (time.perf_counter() - started) * 1000
        _raise_for_auth(resp)

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(
                f"{self.url} returned HTTP {resp.status_code} "
                f"with a non-JSON body: {resp.text[:200]!r}"
            ) from exc

        return _reply_from_json(data, elapsed_ms=elapsed)

    def stream(
        self,
        message: str,
        history: list[dict[str, str]] | None = None,
    ) -> Iterator[Block | ChatReply]:
        """Yield each :class:`Block` as it lands, then the final :class:`ChatReply`.

        The endpoint only emits a block once its JSON object closes, so this is
        block-at-a-time rather than token-at-a-time — but a long answer starts
        rendering well before it finishes.
        """
        started = time.perf_counter()
        blocks: list[Block] = []
        suggestions: list[str] = []
        error: str | None = None

        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    self.url,
                    headers=self._headers(stream=True),
                    json=self._payload(message, history or [], stream=True),
                ) as resp:
                    _raise_for_auth(resp)

                    content_type = resp.headers.get("content-type", "")
                    if "text/event-stream" not in content_type:
                        # The endpoint fell back to a plain JSON body (or an
                        # error). Read it and parse as non-streaming.
                        resp.read()
                        try:
                            data = resp.json()
                        except (json.JSONDecodeError, ValueError) as exc:
                            raise ProtocolError(
                                f"{self.url} answered {content_type or 'no content-type'} "
                                f"with body {resp.text[:200]!r}"
                            ) from exc
                        reply = _reply_from_json(
                            data, elapsed_ms=(time.perf_counter() - started) * 1000
                        )
                        for block in reply.blocks:
                            yield block
                        yield reply
                        return

                    for event, data in _iter_sse(resp.iter_lines()):
                        if event == "block" and isinstance(data, dict):
                            block = parse_blocks([data])
                            if block:
                                blocks.append(block[0])
                                yield block[0]
                        elif event == "done" and isinstance(data, dict):
                            raw = data.get("suggestions") or []
                            suggestions = [str(s) for s in raw][:4]
                        elif event == "error":
                            error = _error_text(data)
        except httpx.HTTPError as exc:
            raise TransportError(f"{self.url}: {exc}") from exc

        if error:
            raise ProtocolError(error)

        yield ChatReply(
            blocks=blocks,
            suggestions=suggestions,
            raw={"blocks": [b.to_dict() for b in blocks], "suggestions": suggestions},
            elapsed_ms=(time.perf_counter() - started) * 1000,
            streamed=True,
        )


class Conversation:
    """A chat session: a client plus the rolling history it feeds back."""

    def __init__(self, client: ChatClient) -> None:
        self.client = client
        self.history: list[dict[str, str]] = []

    def turns(self) -> int:
        return sum(1 for turn in self.history if turn["role"] == "user")

    def clear(self) -> None:
        self.history.clear()

    def send(self, message: str, stream: bool | None = None) -> ChatReply:
        reply = self.client.send(message, self.history, stream=stream)
        self._record(message, reply)
        return reply

    def stream(
        self, message: str, on_block: Callable[[Block], None] | None = None
    ) -> ChatReply:
        reply: ChatReply | None = None
        for event in self.client.stream(message, self.history):
            if isinstance(event, ChatReply):
                reply = event
            elif on_block is not None:
                on_block(event)
        if reply is None:  # pragma: no cover
            raise ProtocolError("stream ended without a terminal event")
        self._record(message, reply)
        return reply

    def _record(self, message: str, reply: ChatReply) -> None:
        self.history.append({"role": "user", "content": message[:_MAX_HISTORY_CONTENT]})
        self.history.append(reply.to_history_turn())
        # The endpoints keep the last 20 turns; holding more just wastes memory.
        limit = self.client.cfg.history_limit
        if limit and len(self.history) > limit:
            self.history = self.history[-limit:]


# ── helpers ─────────────────────────────────────────────────────────────────


def _user_agent() -> str:
    from lory_code_security import __version__

    return f"lory-code-security/{__version__}"


def _raise_for_auth(resp: httpx.Response) -> None:
    if resp.status_code in (401, 403):
        raise AuthError(f"chat endpoint returned HTTP {resp.status_code}")
    if resp.status_code >= 500:
        raise TransportError(f"chat endpoint returned HTTP {resp.status_code}")


def _error_text(data: Any) -> str:
    if isinstance(data, dict):
        return str(data.get("error") or data.get("message") or data)
    return str(data)


def _reply_from_json(data: Any, elapsed_ms: float) -> ChatReply:
    if not isinstance(data, dict):
        raise ProtocolError(f"expected a JSON object, got {type(data).__name__}")

    if data.get("paywall"):
        raise PaywallError(
            str(data.get("error") or "free message limit reached"),
            used=data.get("prompts_used"),
            limit=data.get("prompts_limit"),
        )

    if data.get("success") is False:
        raise ProtocolError(_error_text(data))

    if "blocks" in data:
        blocks = parse_blocks(data.get("blocks"))
        suggestions = [str(s) for s in (data.get("suggestions") or [])][:4]
        return ChatReply(
            blocks=blocks,
            suggestions=suggestions,
            raw=data,
            raw_text=json.dumps(data, ensure_ascii=False),
            elapsed_ms=elapsed_ms,
        )

    # `reply` is the server's own fallback when the model failed to emit the
    # contracted JSON. Surface it rather than erroring, and keep it flagged.
    reply_text = data.get("reply")
    if isinstance(reply_text, str):
        return ChatReply(
            blocks=parse_blocks(reply_text),
            plain_reply=reply_text,
            raw=data,
            raw_text=reply_text,
            elapsed_ms=elapsed_ms,
        )

    raise ProtocolError(f"reply had neither 'blocks' nor 'reply': {list(data)}")


def _iter_sse(lines: Iterator[str]) -> Iterator[tuple[str, Any]]:
    """Parse ``event:``/``data:`` pairs out of an SSE line stream."""
    event = "message"
    data_lines: list[str] = []

    for line in lines:
        line = line.rstrip("\r")
        if line == "":
            if data_lines:
                payload = "\n".join(data_lines)
                try:
                    yield event, json.loads(payload)
                except (json.JSONDecodeError, ValueError):
                    yield event, payload
            event, data_lines = "message", []
            continue
        if line.startswith(":"):
            continue  # comment / keep-alive
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())

    if data_lines:  # stream ended without a trailing blank line
        payload = "\n".join(data_lines)
        try:
            yield event, json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            yield event, payload
