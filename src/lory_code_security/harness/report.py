"""Harness output: live progress, console summary, JSON, and JUnit XML."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from lory_code_security.harness.runner import ScenarioResult, StepResult
from lory_code_security.harness.scenario import Scenario

_MARKS = {"pass": ("[green]✓[/green]", "green"), "fail": ("[red]✗[/red]", "red"),
          "skip": ("[dim]−[/dim]", "dim")}


def live_reporter(console: Console) -> Callable[[str, Any], None]:
    """Progress callback that prints each scenario and step as it runs."""

    def report(event: str, payload: Any) -> None:
        if event == "scenario_start" and isinstance(payload, Scenario):
            console.print()
            console.print(f"[bold]{payload.name}[/bold]  [dim]{payload.description}[/dim]")

        elif event == "scenario_skipped" and isinstance(payload, ScenarioResult):
            console.print()
            console.print(
                f"[dim]−[/dim] [bold]{payload.scenario.name}[/bold] "
                f"[dim]skipped: {payload.skipped_reason}[/dim]"
            )

        elif event == "step_done" and isinstance(payload, StepResult):
            mark = "[green]✓[/green]" if payload.passed else "[red]✗[/red]"
            if payload.step.soft and not payload.passed:
                mark = "[yellow]![/yellow]"
            console.print(
                f"  {mark} {payload.step.label()} [dim]({payload.elapsed_ms:.0f}ms)[/dim]"
            )
            for failure in payload.failures:
                console.print(f"      [red]{failure.name}[/red]: {failure.detail}")
            if payload.observation.error and not payload.failures:
                console.print(f"      [dim]{payload.observation.error}[/dim]")

    return report


def print_summary(console: Console, results: list[ScenarioResult]) -> None:
    console.print()
    table = Table(box=None, header_style="bold cyan", pad_edge=False)
    table.add_column("scenario")
    table.add_column("checks", justify="right")
    table.add_column("failed", justify="right")
    table.add_column("time", justify="right")
    table.add_column("result")

    total_passed = total_failed = total_skipped = 0

    for result in results:
        passed, failed, skipped = result.counts()
        total_passed += passed
        total_failed += failed
        total_skipped += skipped

        if result.skipped:
            verdict = Text("skipped", style="dim")
        elif result.error:
            verdict = Text("error", style="bold red")
        elif result.passed:
            verdict = Text("pass", style="bold green")
        else:
            verdict = Text("FAIL", style="bold red")

        table.add_row(
            Text(result.scenario.name, style="bold"),
            str(passed + failed),
            Text(str(failed), style="red" if failed else "dim"),
            f"{result.elapsed_ms / 1000:.1f}s",
            verdict,
        )

    console.print(table)

    for result in results:
        if result.error:
            console.print(f"\n[red]{result.scenario.name}:[/red] {result.error}")

    failed_scenarios = [r for r in results if not r.passed]
    console.print()
    if failed_scenarios:
        console.print(
            f"[bold red]{len(failed_scenarios)} of {len(results)} scenarios failed[/bold red] "
            f"[dim]({total_passed} checks passed, {total_failed} failed, "
            f"{total_skipped} skipped)[/dim]"
        )
    else:
        console.print(
            f"[bold green]All {len(results)} scenarios passed[/bold green] "
            f"[dim]({total_passed} checks, {total_skipped} skipped)[/dim]"
        )


def to_dict(results: list[ScenarioResult]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "passed": all(r.passed for r in results),
        "scenarios": [
            {
                "name": r.scenario.name,
                "description": r.scenario.description,
                "tags": r.scenario.tags,
                "source": str(r.scenario.source) if r.scenario.source else None,
                "passed": r.passed,
                "skipped": r.skipped,
                "skipped_reason": r.skipped_reason,
                "error": r.error,
                "elapsed_ms": round(r.elapsed_ms, 1),
                "steps": [
                    {
                        "label": s.step.label(),
                        "kind": s.step.kind,
                        "target": s.step.target,
                        "soft": s.step.soft,
                        "passed": s.passed,
                        "elapsed_ms": round(s.elapsed_ms, 1),
                        "error": s.observation.error,
                        "block_types": s.observation.block_types,
                        "checks": [
                            {
                                "name": c.name,
                                "status": c.status,
                                "detail": c.detail,
                            }
                            for c in s.checks
                        ],
                    }
                    for s in r.steps
                ],
            }
            for r in results
        ],
    }


def write_json(results: list[ScenarioResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_dict(results), indent=2))


def write_junit(results: list[ScenarioResult], path: Path) -> None:
    """Emit JUnit XML so CI renders failures natively."""
    suites = ET.Element("testsuites", name="lory-code-security")

    for result in results:
        passed, failed, skipped = result.counts()
        suite = ET.SubElement(
            suites,
            "testsuite",
            name=result.scenario.name,
            tests=str(passed + failed + skipped),
            failures=str(failed),
            skipped=str(skipped),
            time=f"{result.elapsed_ms / 1000:.3f}",
        )

        if result.skipped:
            case = ET.SubElement(suite, "testcase", name=result.scenario.name, classname="scenario")
            ET.SubElement(case, "skipped", message=result.skipped_reason or "")
            continue

        if result.error:
            case = ET.SubElement(suite, "testcase", name=result.scenario.name, classname="scenario")
            ET.SubElement(case, "error", message=result.error)

        for step in result.steps:
            for check in step.checks:
                case = ET.SubElement(
                    suite,
                    "testcase",
                    name=f"{step.step.label()} :: {check.name}",
                    classname=result.scenario.name,
                    time=f"{step.elapsed_ms / 1000:.3f}",
                )
                if check.skipped:
                    ET.SubElement(case, "skipped", message=check.detail)
                elif not check.passed:
                    ET.SubElement(
                        case, "failure", message=check.detail or f"{check.name} failed"
                    ).text = _evidence(step)

    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suites).write(path, encoding="utf-8", xml_declaration=True)


def _evidence(step: StepResult) -> str:
    """What Lory actually said, so a CI failure is diagnosable from the report."""
    observation = step.observation
    body = observation.raw_text or observation.text
    return (body or observation.error or "")[:2000]
