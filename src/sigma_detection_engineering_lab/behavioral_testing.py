"""Running behavioral tests: rules against synthetic fixtures.

A positive fixture asserts the rule matches; a negative fixture asserts it does
not. A rule whose detection falls outside the documented matcher subset yields
``UNSUPPORTED``, never ``PASSED``: an untestable rule must not be able to look
like a tested one in a report.

These tests say whether a rule behaves as its author intended on events the
author wrote. They say nothing about how it would perform on production
telemetry, and no result here should be read as a detection efficacy measurement.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sigma_detection_engineering_lab.constants import EVALUATOR_NAME, SYNTHETIC_TESTING_BANNER
from sigma_detection_engineering_lab.correlation_engine import (
    CorrelationEngine,
    parse_correlation,
)
from sigma_detection_engineering_lab.errors import (
    ConditionSyntaxError,
    CorrelationError,
    MatcherError,
    SdelError,
    UnsupportedConditionError,
    UnsupportedModifierError,
)
from sigma_detection_engineering_lab.event_matcher import (
    DEFAULT_OPTIONS,
    MatchOptions,
    RuleMatcher,
    build_rule_matcher,
)
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.models import (
    CorrelationSequence,
    FixtureCase,
    Rule,
    TestOutcome,
    TestResult,
    TestSummary,
    utc_now_iso,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import correlation_base_documents

UNSUPPORTED_ERRORS = (
    UnsupportedConditionError,
    UnsupportedModifierError,
    ConditionSyntaxError,
    MatcherError,
)


@dataclass(frozen=True)
class TestRunOptions:
    """Knobs for a behavioral test run."""

    match_options: MatchOptions = DEFAULT_OPTIONS
    enforce_logsource: bool = True
    report_untested_rules: bool = True


def _result(
    case_id: str,
    catalog_id: str,
    outcome: TestOutcome,
    *,
    expected: bool,
    actual: bool | None,
    duration: float,
    message: str = "",
    kind: str = "event",
    explanation: Sequence[str] = (),
) -> TestResult:
    return TestResult(
        case_id=case_id,
        catalog_id=catalog_id,
        outcome=outcome,
        expected_match=expected,
        actual_match=actual,
        duration_seconds=duration,
        message=message,
        kind=kind,
        explanation=tuple(explanation),
    )


def run_case(
    matcher: RuleMatcher,
    case: FixtureCase,
) -> TestResult:
    """Evaluate one event fixture and classify the outcome."""
    started = time.perf_counter()
    try:
        evaluation = matcher.evaluate(case.event)
    except SdelError as exc:
        return _result(
            case.case_id,
            case.catalog_id,
            TestOutcome.ERROR,
            expected=case.expects_match,
            actual=None,
            duration=time.perf_counter() - started,
            message=f"evaluation raised {type(exc).__name__}: {exc}",
        )

    duration = time.perf_counter() - started
    matched = evaluation.matched
    if matched == case.expects_match:
        return _result(
            case.case_id,
            case.catalog_id,
            TestOutcome.PASSED,
            expected=case.expects_match,
            actual=matched,
            duration=duration,
            explanation=evaluation.explanation,
        )

    verb = "did not match" if case.expects_match else "matched"
    return _result(
        case.case_id,
        case.catalog_id,
        TestOutcome.FAILED,
        expected=case.expects_match,
        actual=matched,
        duration=duration,
        message=(
            f"{case.kind} fixture {case.event.event_id!r} {verb} unexpectedly ({case.source_path})"
        ),
        explanation=evaluation.explanation,
    )


def build_base_matchers(
    rule: Rule,
    *,
    catalog: RuleCatalog | None,
    options: MatchOptions,
    enforce_logsource: bool,
) -> dict[str, RuleMatcher]:
    """Resolve the base rules a correlation rule references into matchers.

    References are resolved first against base documents inside the correlation
    file, then against the wider catalog by name, UUID, or catalog identifier.

    Raises:
        CorrelationError: if a reference cannot be resolved.
    """
    if rule.correlation is None:
        raise CorrelationError(f"{rule.catalog_id}: rule has no correlation block")

    definition = parse_correlation(rule.correlation, source=f"{rule.catalog_id}.correlation")
    inline = correlation_base_documents(rule)
    matchers: dict[str, RuleMatcher] = {}

    for reference in definition.rules:
        document = inline.get(reference)
        if document is not None:
            logsource = document.get("logsource") or {}
            detection = document.get("detection")
            if not isinstance(detection, Mapping):
                raise CorrelationError(
                    f"{rule.catalog_id}: base document {reference!r} has no detection block"
                )
            matchers[reference] = RuleMatcher(
                detection,
                category=_optional(logsource, "category"),
                product=_optional(logsource, "product"),
                service=_optional(logsource, "service"),
                options=options,
                source=f"{rule.catalog_id}:{reference}",
                enforce_logsource=enforce_logsource,
            )
            continue

        resolved = catalog.resolve(reference) if catalog is not None else None
        if resolved is None or not resolved.detection:
            raise CorrelationError(
                f"{rule.catalog_id}: correlation references {reference!r}, which could not be "
                "resolved to a rule with a detection block"
            )
        matchers[reference] = build_rule_matcher(
            resolved, options=options, enforce_logsource=enforce_logsource
        )
    return matchers


def _optional(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return str(value) if value is not None else None


def run_sequence(
    engine: CorrelationEngine,
    sequence: CorrelationSequence,
) -> TestResult:
    """Evaluate one correlation sequence and classify the outcome."""
    started = time.perf_counter()
    try:
        result = engine.evaluate(sequence.events)
    except SdelError as exc:
        return _result(
            sequence.sequence_id,
            sequence.catalog_id,
            TestOutcome.ERROR,
            expected=sequence.expects_match,
            actual=None,
            duration=time.perf_counter() - started,
            message=f"correlation evaluation raised {type(exc).__name__}: {exc}",
            kind="sequence",
        )

    duration = time.perf_counter() - started
    if result.matched == sequence.expects_match:
        return _result(
            sequence.sequence_id,
            sequence.catalog_id,
            TestOutcome.PASSED,
            expected=sequence.expects_match,
            actual=result.matched,
            duration=duration,
            kind="sequence",
            explanation=result.explanation,
        )

    verb = "did not fire" if sequence.expects_match else "fired"
    return _result(
        sequence.sequence_id,
        sequence.catalog_id,
        TestOutcome.FAILED,
        expected=sequence.expects_match,
        actual=result.matched,
        duration=duration,
        message=(
            f"correlation {verb} unexpectedly over {len(sequence.events)} events "
            f"({sequence.source_path})"
        ),
        kind="sequence",
        explanation=result.explanation,
    )


def run_rule(
    rule: Rule,
    fixtures: FixtureSet,
    *,
    catalog: RuleCatalog | None = None,
    options: TestRunOptions | None = None,
) -> list[TestResult]:
    """Run every fixture registered for one rule."""
    settings = options or TestRunOptions()
    cases = fixtures.cases_for(rule.catalog_id)
    sequences = fixtures.sequences_for(rule.catalog_id)

    if not cases and not sequences:
        if not settings.report_untested_rules:
            return []
        return [
            _result(
                f"{rule.catalog_id}::no-fixtures",
                rule.catalog_id,
                TestOutcome.SKIPPED,
                expected=True,
                actual=None,
                duration=0.0,
                message="no fixtures are registered for this rule",
            )
        ]

    results: list[TestResult] = []

    if rule.is_correlation:
        try:
            definition = parse_correlation(
                rule.correlation or {}, source=f"{rule.catalog_id}.correlation"
            )
            base_matchers = build_base_matchers(
                rule,
                catalog=catalog,
                options=settings.match_options,
                enforce_logsource=settings.enforce_logsource,
            )
            engine = CorrelationEngine(
                definition, base_matchers, source=f"{rule.catalog_id}.correlation"
            )
        except (CorrelationError, *UNSUPPORTED_ERRORS) as exc:
            return [
                _result(
                    f"{rule.catalog_id}::correlation",
                    rule.catalog_id,
                    TestOutcome.UNSUPPORTED,
                    expected=True,
                    actual=None,
                    duration=0.0,
                    message=f"correlation rule is not evaluable: {exc}",
                    kind="sequence",
                )
            ]
        results.extend(run_sequence(engine, sequence) for sequence in sequences)
        if cases:
            results.append(
                _result(
                    f"{rule.catalog_id}::event-fixtures-ignored",
                    rule.catalog_id,
                    TestOutcome.SKIPPED,
                    expected=True,
                    actual=None,
                    duration=0.0,
                    message=(
                        f"{len(cases)} single-event fixture(s) registered for a correlation "
                        "rule were not evaluated; correlation rules are tested with sequences"
                    ),
                    kind="sequence",
                )
            )
        return results

    try:
        matcher = build_rule_matcher(
            rule,
            options=settings.match_options,
            enforce_logsource=settings.enforce_logsource,
        )
    except UNSUPPORTED_ERRORS as exc:
        return [
            _result(
                f"{rule.catalog_id}::detection",
                rule.catalog_id,
                TestOutcome.UNSUPPORTED,
                expected=True,
                actual=None,
                duration=0.0,
                message=f"detection is outside the documented matcher subset: {exc}",
            )
        ]

    results.extend(run_case(matcher, case) for case in cases)
    if sequences:
        results.append(
            _result(
                f"{rule.catalog_id}::sequences-ignored",
                rule.catalog_id,
                TestOutcome.SKIPPED,
                expected=True,
                actual=None,
                duration=0.0,
                message=(
                    f"{len(sequences)} correlation sequence(s) registered for a "
                    "non-correlation rule were not evaluated"
                ),
                kind="sequence",
            )
        )
    return results


def run_catalog(
    catalog: RuleCatalog,
    fixtures: FixtureSet,
    *,
    options: TestRunOptions | None = None,
    only: Sequence[str] | None = None,
) -> TestSummary:
    """Run behavioral tests across the catalog and summarise the outcome."""
    settings = options or TestRunOptions()
    selected = set(only) if only else None

    results: list[TestResult] = []
    for rule in catalog:
        if selected is not None and rule.catalog_id not in selected:
            continue
        results.extend(run_rule(rule, fixtures, catalog=catalog, options=settings))

    return TestSummary(
        results=tuple(results),
        generated_at=utc_now_iso(),
        evaluator=EVALUATOR_NAME,
    )


def summarise(summary: TestSummary) -> dict[str, Any]:
    """Return a serialisable overview, carrying the mandatory testing banner."""
    per_rule: dict[str, dict[str, int]] = {}
    for result in summary.results:
        bucket = per_rule.setdefault(
            result.catalog_id,
            {"passed": 0, "failed": 0, "errored": 0, "skipped": 0, "unsupported": 0},
        )
        key = {
            TestOutcome.PASSED: "passed",
            TestOutcome.FAILED: "failed",
            TestOutcome.ERROR: "errored",
            TestOutcome.SKIPPED: "skipped",
            TestOutcome.UNSUPPORTED: "unsupported",
        }[result.outcome]
        bucket[key] += 1

    return {
        "banner": SYNTHETIC_TESTING_BANNER,
        "evaluator": summary.evaluator or EVALUATOR_NAME,
        "generated_at": summary.generated_at,
        "totals": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "errored": summary.errored,
            "skipped": summary.skipped,
            "unsupported": summary.unsupported,
        },
        "successful": summary.successful,
        "per_rule": dict(sorted(per_rule.items())),
    }


def failing_results(summary: TestSummary) -> tuple[TestResult, ...]:
    """Return results that should block a run: failures, errors, and unsupported."""
    blocking = {TestOutcome.FAILED, TestOutcome.ERROR, TestOutcome.UNSUPPORTED}
    return tuple(result for result in summary.results if result.outcome in blocking)


__all__ = [
    "SYNTHETIC_TESTING_BANNER",
    "TestRunOptions",
    "build_base_matchers",
    "failing_results",
    "run_case",
    "run_catalog",
    "run_rule",
    "run_sequence",
    "summarise",
]
