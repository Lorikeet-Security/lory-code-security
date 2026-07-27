"""``lory harness`` — run YAML scenarios against Lory."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.table import Table
from rich.text import Text

from lory_code_security.cli.common import CONFIG_OPTION, console, die, load_config
from lory_code_security.core.errors import ConfigError


@click.group()
def harness() -> None:
    """Run YAML scenarios against Lory.

    Lory's behaviour lives in markdown skill files that are hot-editable from
    the admin console with no regression net behind them. The harness is that
    net: assert on the block contract, on guardrails, and on MCP behaviour,
    from CI.
    """


@harness.command("run")
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
@CONFIG_OPTION
@click.option("--tag", "tags", multiple=True, help="Only run scenarios with this tag.")
@click.option("--json-out", type=click.Path(dir_okay=False, path_type=Path),
              help="Write a JSON report.")
@click.option("--junit-out", type=click.Path(dir_okay=False, path_type=Path),
              help="Write a JUnit XML report for CI.")
@click.option("--quiet", "-q", is_flag=True, help="Only print the summary.")
def harness_run(
    paths: tuple[str, ...], config_path: str, tags: tuple[str, ...],
    json_out: Path | None, junit_out: Path | None, quiet: bool,
) -> None:
    """Run every scenario under PATHS and report.

    Exits non-zero if any scenario fails, so it drops straight into CI.
    """
    from lory_code_security.harness import Runner, load_scenarios, write_json, write_junit
    from lory_code_security.harness.report import live_reporter, print_summary

    cfg = load_config(config_path)
    try:
        scenarios = load_scenarios(list(paths))
    except ConfigError as exc:
        die(str(exc))
        return

    if tags:
        scenarios = [s for s in scenarios if s.matches(list(tags))]
        if not scenarios:
            die(f"no scenarios matched tag(s): {', '.join(tags)}")

    runner = Runner(cfg, on_event=None if quiet else live_reporter(console))
    results = runner.run_all(scenarios)

    print_summary(console, results)

    if json_out:
        write_json(results, json_out)
        console.print(f"[dim]JSON report: {json_out}[/dim]")
    if junit_out:
        write_junit(results, junit_out)
        console.print(f"[dim]JUnit report: {junit_out}[/dim]")

    sys.exit(0 if all(r.passed for r in results) else 1)


@harness.command("checks")
def harness_checks() -> None:
    """List the assertions scenarios can use."""
    from lory_code_security.harness import checks as checks_module

    table = Table(box=None, header_style="bold cyan", pad_edge=False)
    table.add_column("check")
    table.add_column("what it asserts")
    for name in checks_module.available():
        doc = (checks_module.describe(name) or "").strip()
        table.add_row(Text(name, style="bold"), Text(doc))
    console.print(table)


@harness.command("lint")
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
def harness_lint(paths: tuple[str, ...]) -> None:
    """Parse scenarios and report problems without contacting Lory."""
    from lory_code_security.harness import checks as checks_module
    from lory_code_security.harness import load_scenarios

    try:
        scenarios = load_scenarios(list(paths))
    except ConfigError as exc:
        die(str(exc))
        return

    known = set(checks_module.available())
    problems: list[str] = []
    for scenario in scenarios:
        for step in scenario.steps:
            for spec in step.expect:
                if spec["name"] not in known:
                    problems.append(
                        f"{scenario.name} / {step.label()}: unknown check {spec['name']!r}"
                    )

    for problem in problems:
        console.print(f"[red]✗[/red] {problem}")

    if problems:
        die(f"{len(problems)} problem(s) in {len(scenarios)} scenario(s)")
    console.print(
        f"[green]✓[/green] {len(scenarios)} scenario(s), "
        f"{sum(len(s.steps) for s in scenarios)} step(s), no problems"
    )
