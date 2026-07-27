"""Executes scenarios against a live Lory."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lory_code_security.client.chat import ChatClient, Conversation
from lory_code_security.client.mcp import McpClient
from lory_code_security.core.config import Config
from lory_code_security.core.errors import LoryConsoleError
from lory_code_security.domain.blocks import Block
from lory_code_security.harness.checks import CheckResult, Observation, run_check
from lory_code_security.harness.scenario import Scenario, Step


@dataclass
class StepResult:
    step: Step
    observation: Observation
    checks: list[CheckResult] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if not c.skipped)

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed and not c.skipped]


@dataclass
class ScenarioResult:
    scenario: Scenario
    steps: list[StepResult] = field(default_factory=list)
    skipped_reason: str | None = None
    error: str | None = None
    elapsed_ms: float = 0.0

    @property
    def skipped(self) -> bool:
        return self.skipped_reason is not None

    @property
    def passed(self) -> bool:
        if self.skipped:
            return True
        if self.error:
            return False
        return all(s.passed for s in self.steps if not s.step.soft)

    def counts(self) -> tuple[int, int, int]:
        """(passed, failed, skipped) over every check in the scenario."""
        passed = failed = skipped = 0
        for step in self.steps:
            for check in step.checks:
                if check.skipped:
                    skipped += 1
                elif check.passed:
                    passed += 1
                else:
                    failed += 1
        return passed, failed, skipped


ProgressFn = Callable[[str, Any], None]


class Runner:
    """Runs scenarios and collects results. Stateless between scenarios."""

    def __init__(
        self,
        cfg: Config,
        on_event: ProgressFn | None = None,
        stream: bool = False,
    ) -> None:
        self.cfg = cfg
        self.on_event = on_event or (lambda event, payload: None)
        # Streaming loses the raw model bytes, which the fence check needs, so
        # the harness defaults to blocking requests even when the TUI streams.
        self.stream = stream
        self._mcp: McpClient | None = None
        self._mcp_failed: str | None = None

    # ── entry points ────────────────────────────────────────────────────────

    def run_all(self, scenarios: list[Scenario]) -> list[ScenarioResult]:
        return [self.run(s) for s in scenarios]

    def run(self, scenario: Scenario) -> ScenarioResult:
        started = time.perf_counter()
        result = ScenarioResult(scenario=scenario)

        skip = self._skip_reason(scenario)
        if skip:
            result.skipped_reason = skip
            self.on_event("scenario_skipped", result)
            return result

        self.on_event("scenario_start", scenario)

        conversations: dict[str, Conversation] = {}
        try:
            for step in scenario.steps:
                step_result = self._run_step(step, scenario, conversations)
                result.steps.append(step_result)
                self.on_event("step_done", step_result)
        except LoryConsoleError as exc:
            # A scenario-level failure (bad config, dead endpoint) is not a
            # behavioural finding; record it separately from check failures.
            result.error = str(exc)

        result.elapsed_ms = (time.perf_counter() - started) * 1000
        self.on_event("scenario_done", result)
        return result

    # ── steps ───────────────────────────────────────────────────────────────

    def _run_step(
        self,
        step: Step,
        scenario: Scenario,
        conversations: dict[str, Conversation],
    ) -> StepResult:
        self.on_event("step_start", step)
        started = time.perf_counter()

        if step.kind == "chat":
            observation = self._observe_chat(step, scenario, conversations)
        else:
            observation = self._observe_mcp(step)

        elapsed = (time.perf_counter() - started) * 1000
        observation.elapsed_ms = elapsed

        checks = [
            run_check(spec["name"], observation, spec["args"]) for spec in step.expect
        ]
        # A step with no explicit expectations still asserts that it worked.
        if not checks:
            checks = [run_check("ok", observation, {})]

        return StepResult(step=step, observation=observation, checks=checks, elapsed_ms=elapsed)

    def _observe_chat(
        self,
        step: Step,
        scenario: Scenario,
        conversations: dict[str, Conversation],
    ) -> Observation:
        surface = step.surface or scenario.surface
        conversation = conversations.get(surface)
        if conversation is None:
            conversation = Conversation(ChatClient(self.cfg, surface))
            conversations[surface] = conversation
        if step.fresh:
            conversation.clear()

        try:
            reply = conversation.send(step.target, stream=self.stream)
        except LoryConsoleError as exc:
            return Observation(kind="chat", ok=False, error=f"{type(exc).__name__}: {exc}")

        return Observation(
            kind="chat",
            ok=True,
            text=reply.text(),
            raw_text=reply.raw_text or "",
            blocks=list(reply.blocks),
            suggestions=list(reply.suggestions),
            structured=reply.raw,
            contract_problems=reply.contract_problems(),
        )

    def _observe_mcp(self, step: Step) -> Observation:
        try:
            client = self._mcp_client()
        except LoryConsoleError as exc:
            return Observation(kind="mcp", ok=False, error=str(exc))

        try:
            result = client.call_tool(step.target, step.args)
        except LoryConsoleError as exc:
            return Observation(kind="mcp", ok=False, error=f"{type(exc).__name__}: {exc}")

        return Observation(
            kind="mcp",
            ok=not result.is_error,
            text=result.text,
            raw_text=result.text,
            structured=result.structured,
            error="tool reported isError" if result.is_error else None,
        )

    # ── shared MCP session ──────────────────────────────────────────────────

    def _mcp_client(self) -> McpClient:
        if self._mcp_failed:
            raise LoryConsoleError(self._mcp_failed)
        if self._mcp is None:
            try:
                client = McpClient(self.cfg)
                client.initialize()
            except LoryConsoleError as exc:
                self._mcp_failed = f"MCP unavailable: {exc}"
                raise
            self._mcp = client
        return self._mcp

    def _skip_reason(self, scenario: Scenario) -> str | None:
        if scenario.requires_mcp and not self.cfg.has_mcp():
            return "no mcp_token configured"
        if scenario.requires_portal and not self.cfg.session_cookie:
            return "no session_cookie configured"
        return None


def blocks_summary(blocks: list[Block]) -> str:
    return ", ".join(b.type for b in blocks) or "(none)"
