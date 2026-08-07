"""JUnit XML output for behavioral test results.

JUnit is the lingua franca of CI test reporting, so behavioral results are
emitted in it directly. One mapping decision matters: an ``UNSUPPORTED`` result
is written as a **failure**, not as ``skipped``. CI systems treat skips as
acceptable, and a rule that cannot be evaluated must not be able to reach a green
build by being quietly skipped.

Genuine skips — a rule with no fixtures registered at all — are written as
``skipped`` and are caught instead by the fixture-minimum quality gates.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from sigma_detection_engineering_lab.constants import SYNTHETIC_TESTING_BANNER
from sigma_detection_engineering_lab.models import TestOutcome, TestResult, TestSummary

SUITE_NAME = "sigma-detection-engineering-lab"

UNSUPPORTED_FAILURE_NOTE = (
    "An unsupported rule is reported as a failure so it cannot pass by default."
)


def _attribute(value: object) -> str:
    return quoteattr(str(value))


def _group_by_rule(results: Sequence[TestResult]) -> dict[str, list[TestResult]]:
    grouped: dict[str, list[TestResult]] = {}
    for result in results:
        grouped.setdefault(result.catalog_id, []).append(result)
    return dict(sorted(grouped.items()))


def _render_case(result: TestResult, indent: str) -> list[str]:
    lines = [
        f"{indent}<testcase name={_attribute(result.case_id)} "
        f"classname={_attribute(result.catalog_id)} "
        f"time={_attribute(f'{result.duration_seconds:.6f}')}>"
    ]
    detail = escape("\n".join(result.explanation)) if result.explanation else ""

    if result.outcome is TestOutcome.FAILED:
        lines.append(
            f"{indent}  <failure message={_attribute(result.message or 'expectation not met')} "
            f'type="behavioral-expectation">{detail}</failure>'
        )
    elif result.outcome is TestOutcome.ERROR:
        lines.append(
            f"{indent}  <error message={_attribute(result.message or 'evaluation error')} "
            f'type="evaluation-error">{detail}</error>'
        )
    elif result.outcome is TestOutcome.UNSUPPORTED:
        message = (
            result.message
            or "rule is outside the documented evaluator subset and was not evaluated"
        )
        lines.append(
            f"{indent}  <failure message={_attribute(message)} "
            f'type="unsupported-construct">'
            f"{escape(UNSUPPORTED_FAILURE_NOTE)}"
            f"</failure>"
        )
    elif result.outcome is TestOutcome.SKIPPED:
        lines.append(f"{indent}  <skipped message={_attribute(result.message or 'no fixtures')}/>")
    elif detail:
        lines.append(f"{indent}  <system-out>{detail}</system-out>")

    lines.append(f"{indent}</testcase>")
    return lines


def render_junit(summary: TestSummary, *, suite_name: str = SUITE_NAME) -> str:
    """Render a :class:`TestSummary` as a JUnit XML document."""
    grouped = _group_by_rule(summary.results)
    total_time = sum(result.duration_seconds for result in summary.results)

    # Unsupported results are counted as failures here to match how they are
    # rendered, so the header totals agree with the case elements.
    failures = summary.failed + summary.unsupported

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f"<!-- {escape(SYNTHETIC_TESTING_BANNER)} -->",
        f"<testsuites name={_attribute(suite_name)} tests={_attribute(summary.total)} "
        f"failures={_attribute(failures)} errors={_attribute(summary.errored)} "
        f"skipped={_attribute(summary.skipped)} time={_attribute(f'{total_time:.6f}')}>",
    ]

    for catalog_id, results in grouped.items():
        suite_failures = sum(
            1
            for result in results
            if result.outcome in (TestOutcome.FAILED, TestOutcome.UNSUPPORTED)
        )
        suite_errors = sum(1 for result in results if result.outcome is TestOutcome.ERROR)
        suite_skipped = sum(1 for result in results if result.outcome is TestOutcome.SKIPPED)
        suite_time = sum(result.duration_seconds for result in results)

        lines.append(
            f"  <testsuite name={_attribute(catalog_id)} tests={_attribute(len(results))} "
            f"failures={_attribute(suite_failures)} errors={_attribute(suite_errors)} "
            f"skipped={_attribute(suite_skipped)} time={_attribute(f'{suite_time:.6f}')}>"
        )
        lines.append("    <properties>")
        lines.append(f'      <property name="evaluator" value={_attribute(summary.evaluator)}/>')
        lines.append(
            f'      <property name="data-source" value={_attribute(SYNTHETIC_TESTING_BANNER)}/>'
        )
        lines.append("    </properties>")
        for result in results:
            lines.extend(_render_case(result, "    "))
        lines.append("  </testsuite>")

    lines.append("</testsuites>")
    return "\n".join(lines) + "\n"


def write_junit(summary: TestSummary, destination: Path, *, suite_name: str = SUITE_NAME) -> Path:
    """Write the JUnit document to ``destination`` with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_junit(summary, suite_name=suite_name))
    return destination


__all__ = ["SUITE_NAME", "render_junit", "write_junit"]
