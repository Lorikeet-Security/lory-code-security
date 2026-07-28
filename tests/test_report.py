"""Harness reporting: soft steps, counts, JUnit, and the observation of errors."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from rich.console import Console

from lory_code_security.harness.checks import CheckResult, Observation
from lory_code_security.harness.report import print_summary, to_dict, write_junit
from lory_code_security.harness.runner import ScenarioResult, StepResult
from lory_code_security.harness.scenario import Scenario, Step


def step_result(name: str, *, soft: bool, passed: bool) -> StepResult:
    return StepResult(
        step=Step(kind="chat", target="hi", name=name, soft=soft),
        observation=Observation(kind="chat", ok=True, text="a reply"),
        checks=[CheckResult("contains", passed, "" if passed else "'x' not present")],
        elapsed_ms=12.0,
    )


def scenario_result(*steps: StepResult) -> ScenarioResult:
    scenario = Scenario(name="s", steps=[s.step for s in steps], description="d")
    return ScenarioResult(scenario=scenario, steps=list(steps), elapsed_ms=120.0)


# ── counts ──────────────────────────────────────────────────────────────────


def test_a_soft_failure_is_counted_apart_from_a_real_one():
    result = scenario_result(
        step_result("hard pass", soft=False, passed=True),
        step_result("soft fail", soft=True, passed=False),
    )
    passed, failed, skipped, soft = result.counts()
    assert (passed, failed, skipped, soft) == (1, 0, 0, 1)
    assert result.passed


def test_a_hard_failure_still_fails_the_scenario():
    result = scenario_result(step_result("hard fail", soft=False, passed=False))
    passed, failed, skipped, soft = result.counts()
    assert (passed, failed, skipped, soft) == (0, 1, 0, 0)
    assert not result.passed


# ── console summary ─────────────────────────────────────────────────────────


def render_summary(result: ScenarioResult) -> str:
    console = Console(record=True, width=100, force_terminal=False)
    print_summary(console, [result])
    return console.export_text()


def test_a_soft_only_run_does_not_report_a_failure():
    """The verdict said `pass` while the failed column said 1."""
    text = render_summary(scenario_result(
        step_result("hard pass", soft=False, passed=True),
        step_result("soft fail", soft=True, passed=False),
    ))
    assert "All 1 scenarios passed" in text
    assert "1 soft" in text
    assert "failed" not in text.split("All 1 scenarios passed")[1]


def test_the_summary_counts_every_check_it_ran():
    text = render_summary(scenario_result(
        step_result("hard pass", soft=False, passed=True),
        step_result("soft fail", soft=True, passed=False),
    ))
    assert "2 checks passed" not in text  # only one actually passed
    assert "1 checks passed" in text


# ── JUnit ───────────────────────────────────────────────────────────────────


def test_junit_does_not_mark_a_soft_failure_as_a_failure(tmp_path):
    """A <failure> here turned CI red on a run the harness exits 0 on."""
    path = tmp_path / "junit.xml"
    write_junit([scenario_result(
        step_result("hard pass", soft=False, passed=True),
        step_result("soft fail", soft=True, passed=False),
    )], path)

    suite = ET.parse(path).getroot().find("testsuite")
    assert suite.get("failures") == "0"
    assert suite.get("skipped") == "1"
    assert suite.find(".//failure") is None

    skipped = suite.find(".//skipped")
    assert skipped.get("message").startswith("soft:")
    assert "not present" in skipped.get("message")


def test_junit_still_reports_a_real_failure(tmp_path):
    path = tmp_path / "junit.xml"
    write_junit([scenario_result(step_result("hard fail", soft=False, passed=False))], path)

    suite = ET.parse(path).getroot().find("testsuite")
    assert suite.get("failures") == "1"
    failure = suite.find(".//failure")
    assert failure is not None
    assert "a reply" in (failure.text or "")  # evidence for diagnosis


# ── JSON ────────────────────────────────────────────────────────────────────


def test_json_report_breaks_the_counts_out():
    payload = to_dict([scenario_result(
        step_result("hard pass", soft=False, passed=True),
        step_result("soft fail", soft=True, passed=False),
    )])
    assert payload["passed"] is True
    assert payload["scenarios"][0]["counts"] == {
        "passed": 1, "failed": 0, "skipped": 0, "soft_failed": 1,
    }
