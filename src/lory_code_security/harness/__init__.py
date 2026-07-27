"""Scenario harness for Lory.

Lory's behaviour is defined by markdown skill files that are hot-editable from
the admin console, with no regression net behind them. A malformed edit to
``response-format-blocks.md`` breaks every chat surface at once, and the first
signal today is a user complaint.

This package is the missing net: declarative YAML scenarios, run headless
against a live Lory, asserting on what actually comes back.
"""

from lory_code_security.harness.report import write_json, write_junit
from lory_code_security.harness.runner import Runner, ScenarioResult, StepResult
from lory_code_security.harness.scenario import Scenario, Step, load_scenarios

__all__ = [
    "Runner",
    "Scenario",
    "ScenarioResult",
    "Step",
    "StepResult",
    "load_scenarios",
    "write_json",
    "write_junit",
]
