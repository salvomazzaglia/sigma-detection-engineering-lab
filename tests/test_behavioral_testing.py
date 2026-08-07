"""Behavioral testing: rules evaluated against synthetic fixtures."""

from __future__ import annotations

from typing import Any

import pytest
from tests.conftest import make_case, make_event, make_rule, make_sequence

from sigma_detection_engineering_lab.behavioral_testing import (
    TestRunOptions as RunOptions,
)
from sigma_detection_engineering_lab.behavioral_testing import (
    build_base_matchers,
    failing_results,
    run_case,
    run_catalog,
    run_rule,
    run_sequence,
    summarise,
)
from sigma_detection_engineering_lab.correlation_engine import CorrelationEngine, parse_correlation
from sigma_detection_engineering_lab.errors import CorrelationError
from sigma_detection_engineering_lab.event_matcher import DEFAULT_OPTIONS, build_rule_matcher
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.models import (
    FixtureKind,
)
from sigma_detection_engineering_lab.models import (
    TestOutcome as Outcome,
)
from sigma_detection_engineering_lab.models import (
    TestSummary as Summary,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog

MATCHING_DETECTION = {"selection": {"Image|endswith": "\\synthetic.exe"}, "condition": "selection"}

MATCHING_EVENT = make_event(fields={"Image": "C:\\Synthetic\\synthetic.exe"})
NON_MATCHING_EVENT = make_event("EVT-002", fields={"Image": "C:\\Windows\\explorer.exe"})


def simple_matcher(**kwargs: Any) -> Any:
    return build_rule_matcher(make_rule(detection=MATCHING_DETECTION), **kwargs)


def correlation_rule(catalog_id: str = "SDEL-COR-001", **correlation: Any) -> Any:
    block: dict[str, Any] = {
        "type": "event_count",
        "rules": ["base_rule"],
        "timespan": "5m",
        "group-by": ["host"],
        "condition": {"gte": 2},
    }
    block.update(correlation)
    base_document = {
        "title": "Base",
        "name": "base_rule",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": MATCHING_DETECTION,
    }
    return make_rule(
        catalog_id,
        rule_id="99999999-8888-4777-8666-555555555555",
        is_correlation=True,
        correlation=block,
        documents=[base_document, {"title": "C", "correlation": block}],
    )


class TestRunCase:
    def test_a_matching_positive_case_passes(self) -> None:
        case = make_case(event=MATCHING_EVENT)
        assert run_case(simple_matcher(), case).outcome is Outcome.PASSED

    def test_a_non_matching_positive_case_fails(self) -> None:
        case = make_case(event=NON_MATCHING_EVENT)
        assert run_case(simple_matcher(), case).outcome is Outcome.FAILED

    def test_a_non_matching_negative_case_passes(self) -> None:
        case = make_case(kind=FixtureKind.NEGATIVE, event=NON_MATCHING_EVENT)
        assert run_case(simple_matcher(), case).outcome is Outcome.PASSED

    def test_a_matching_negative_case_fails(self) -> None:
        case = make_case(kind=FixtureKind.NEGATIVE, event=MATCHING_EVENT)
        assert run_case(simple_matcher(), case).outcome is Outcome.FAILED

    def test_the_result_records_the_expected_outcome(self) -> None:
        result = run_case(simple_matcher(), make_case(event=MATCHING_EVENT))
        assert result.expected_match is True

    def test_the_result_records_the_actual_outcome(self) -> None:
        result = run_case(simple_matcher(), make_case(event=NON_MATCHING_EVENT))
        assert result.actual_match is False

    def test_the_result_carries_the_case_id(self) -> None:
        case = make_case(event=MATCHING_EVENT, case_id="explicit-id")
        assert run_case(simple_matcher(), case).case_id == "explicit-id"

    def test_the_result_carries_the_catalog_id(self) -> None:
        case = make_case("SDEL-XYZ-001", event=MATCHING_EVENT)
        assert run_case(simple_matcher(), case).catalog_id == "SDEL-XYZ-001"

    def test_the_result_is_an_event_kind(self) -> None:
        assert run_case(simple_matcher(), make_case(event=MATCHING_EVENT)).kind == "event"

    def test_a_failure_message_names_the_source_file(self) -> None:
        case = make_case(event=NON_MATCHING_EVENT, source_path="fixtures/a.jsonl")
        assert "fixtures/a.jsonl" in run_case(simple_matcher(), case).message

    def test_a_failure_message_describes_the_direction(self) -> None:
        case = make_case(event=NON_MATCHING_EVENT)
        assert "did not match" in run_case(simple_matcher(), case).message

    def test_a_negative_failure_message_describes_the_direction(self) -> None:
        case = make_case(kind=FixtureKind.NEGATIVE, event=MATCHING_EVENT)
        assert "matched unexpectedly" in run_case(simple_matcher(), case).message

    def test_a_pass_carries_no_message(self) -> None:
        assert run_case(simple_matcher(), make_case(event=MATCHING_EVENT)).message == ""

    def test_the_duration_is_recorded(self) -> None:
        assert run_case(simple_matcher(), make_case(event=MATCHING_EVENT)).duration_seconds >= 0

    def test_an_explanation_is_produced(self) -> None:
        assert run_case(simple_matcher(), make_case(event=MATCHING_EVENT)).explanation


class TestRunRule:
    def test_a_rule_with_no_fixtures_is_skipped(self) -> None:
        results = run_rule(make_rule(), FixtureSet())
        assert [result.outcome for result in results] == [Outcome.SKIPPED]

    def test_the_skip_explains_itself(self) -> None:
        assert "no fixtures" in run_rule(make_rule(), FixtureSet())[0].message

    def test_untested_rules_can_be_suppressed(self) -> None:
        options = RunOptions(report_untested_rules=False)
        assert run_rule(make_rule(), FixtureSet(), options=options) == []

    def test_every_registered_case_is_run(self) -> None:
        fixtures = FixtureSet(
            cases=(
                make_case(event=MATCHING_EVENT),
                make_case(kind=FixtureKind.NEGATIVE, event=NON_MATCHING_EVENT),
            )
        )
        results = run_rule(make_rule(detection=MATCHING_DETECTION), fixtures)
        assert len(results) == 2

    def test_all_pass_for_well_formed_fixtures(self) -> None:
        fixtures = FixtureSet(
            cases=(
                make_case(event=MATCHING_EVENT),
                make_case(kind=FixtureKind.NEGATIVE, event=NON_MATCHING_EVENT),
            )
        )
        results = run_rule(make_rule(detection=MATCHING_DETECTION), fixtures)
        assert all(result.outcome is Outcome.PASSED for result in results)

    def test_only_fixtures_for_this_rule_are_used(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case("SDEL-TST-001", event=MATCHING_EVENT), make_case("OTHER"))
        )
        results = run_rule(make_rule(detection=MATCHING_DETECTION), fixtures)
        assert len(results) == 1

    def test_an_unsupported_detection_is_reported(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image": "x"}, "condition": "selection | count() > 3"}
        )
        fixtures = FixtureSet(cases=(make_case(event=MATCHING_EVENT),))
        results = run_rule(rule, fixtures)
        assert [result.outcome for result in results] == [Outcome.UNSUPPORTED]

    def test_an_unsupported_detection_never_reports_a_pass(self) -> None:
        rule = make_rule(detection={"selection": {"Image|weird": "x"}, "condition": "selection"})
        fixtures = FixtureSet(cases=(make_case(event=MATCHING_EVENT),))
        outcomes = {result.outcome for result in run_rule(rule, fixtures)}
        assert Outcome.PASSED not in outcomes

    def test_the_unsupported_message_explains_the_subset(self) -> None:
        rule = make_rule(detection={"selection": {"Image|weird": "x"}, "condition": "selection"})
        fixtures = FixtureSet(cases=(make_case(event=MATCHING_EVENT),))
        assert "matcher subset" in run_rule(rule, fixtures)[0].message

    def test_sequences_on_a_plain_rule_are_skipped(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case(event=MATCHING_EVENT),),
            sequences=(make_sequence("SDEL-TST-001", events=(MATCHING_EVENT,)),),
        )
        results = run_rule(make_rule(detection=MATCHING_DETECTION), fixtures)
        assert any(result.outcome is Outcome.SKIPPED for result in results)

    def test_the_skip_for_sequences_is_a_sequence_kind(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case(event=MATCHING_EVENT),),
            sequences=(make_sequence("SDEL-TST-001", events=(MATCHING_EVENT,)),),
        )
        results = run_rule(make_rule(detection=MATCHING_DETECTION), fixtures)
        skip = next(r for r in results if r.outcome is Outcome.SKIPPED)
        assert skip.kind == "sequence"

    def test_logsource_enforcement_can_be_disabled(self) -> None:
        rule = make_rule(detection=MATCHING_DETECTION)
        mismatched = make_event(fields={"Image": "C:\\a\\synthetic.exe"}, category="network")
        fixtures = FixtureSet(cases=(make_case(event=mismatched),))
        strict = run_rule(rule, fixtures, options=RunOptions(enforce_logsource=True))
        relaxed = run_rule(rule, fixtures, options=RunOptions(enforce_logsource=False))
        assert strict[0].outcome is Outcome.FAILED
        assert relaxed[0].outcome is Outcome.PASSED


class TestCorrelationRuns:
    def test_a_firing_sequence_passes(self) -> None:
        events = (
            make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}, offset_seconds=0),
            make_event("E2", fields={"Image": "C:\\a\\synthetic.exe"}, offset_seconds=10),
        )
        fixtures = FixtureSet(sequences=(make_sequence("SDEL-COR-001", events=events),))
        results = run_rule(correlation_rule(), fixtures)
        assert [result.outcome for result in results] == [Outcome.PASSED]

    def test_a_quiet_sequence_fails_a_positive_expectation(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        fixtures = FixtureSet(sequences=(make_sequence("SDEL-COR-001", events=events),))
        assert run_rule(correlation_rule(), fixtures)[0].outcome is Outcome.FAILED

    def test_a_quiet_sequence_passes_a_negative_expectation(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        fixtures = FixtureSet(
            sequences=(make_sequence("SDEL-COR-001", kind=FixtureKind.NEGATIVE, events=events),)
        )
        assert run_rule(correlation_rule(), fixtures)[0].outcome is Outcome.PASSED

    def test_results_are_sequence_kind(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        fixtures = FixtureSet(sequences=(make_sequence("SDEL-COR-001", events=events),))
        assert run_rule(correlation_rule(), fixtures)[0].kind == "sequence"

    def test_event_fixtures_on_a_correlation_rule_are_skipped(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case("SDEL-COR-001", event=MATCHING_EVENT),),
            sequences=(make_sequence("SDEL-COR-001", events=(MATCHING_EVENT,)),),
        )
        results = run_rule(correlation_rule(), fixtures)
        assert any("were not evaluated" in result.message for result in results)

    def test_an_unresolvable_base_rule_is_unsupported(self) -> None:
        rule = make_rule(
            "SDEL-COR-002",
            is_correlation=True,
            correlation={
                "type": "event_count",
                "rules": ["missing_base"],
                "timespan": "5m",
                "condition": {"gte": 1},
            },
        )
        fixtures = FixtureSet(sequences=(make_sequence("SDEL-COR-002", events=(MATCHING_EVENT,)),))
        assert run_rule(rule, fixtures)[0].outcome is Outcome.UNSUPPORTED

    def test_a_malformed_correlation_block_is_unsupported(self) -> None:
        rule = make_rule(
            "SDEL-COR-003", is_correlation=True, correlation={"type": "not-a-real-type"}
        )
        fixtures = FixtureSet(sequences=(make_sequence("SDEL-COR-003", events=(MATCHING_EVENT,)),))
        assert run_rule(rule, fixtures)[0].outcome is Outcome.UNSUPPORTED


class TestBuildBaseMatchers:
    def test_inline_base_documents_are_resolved(self) -> None:
        matchers = build_base_matchers(
            correlation_rule(),
            catalog=None,
            options=DEFAULT_OPTIONS,
            enforce_logsource=True,
        )
        assert set(matchers) == {"base_rule"}

    def test_the_catalog_resolves_external_references(self) -> None:
        base = make_rule("base_catalog_id", rule_id="uuid-base", detection=MATCHING_DETECTION)
        rule = make_rule(
            "SDEL-COR-004",
            rule_id="uuid-corr",
            is_correlation=True,
            correlation={
                "type": "event_count",
                "rules": ["base_catalog_id"],
                "timespan": "5m",
                "condition": {"gte": 1},
            },
        )
        matchers = build_base_matchers(
            rule,
            catalog=RuleCatalog([base, rule]),
            options=DEFAULT_OPTIONS,
            enforce_logsource=True,
        )
        assert set(matchers) == {"base_catalog_id"}

    def test_a_rule_without_a_correlation_block_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="no correlation block"):
            build_base_matchers(
                make_rule(), catalog=None, options=DEFAULT_OPTIONS, enforce_logsource=True
            )

    def test_an_unresolvable_reference_is_refused(self) -> None:
        rule = make_rule(
            "SDEL-COR-005",
            is_correlation=True,
            correlation={
                "type": "event_count",
                "rules": ["nowhere"],
                "timespan": "5m",
                "condition": {"gte": 1},
            },
        )
        with pytest.raises(CorrelationError, match="could not be"):
            build_base_matchers(rule, catalog=None, options=DEFAULT_OPTIONS, enforce_logsource=True)

    def test_a_base_document_without_detection_is_refused(self) -> None:
        block = {
            "type": "event_count",
            "rules": ["base_rule"],
            "timespan": "5m",
            "condition": {"gte": 1},
        }
        rule = make_rule(
            "SDEL-COR-006",
            is_correlation=True,
            correlation=block,
            documents=[
                {"title": "Base", "name": "base_rule", "detection": "not-a-mapping"},
                {"title": "C", "correlation": block},
            ],
        )
        with pytest.raises(CorrelationError, match="no detection block"):
            build_base_matchers(rule, catalog=None, options=DEFAULT_OPTIONS, enforce_logsource=True)


class TestRunSequence:
    def engine(self, **correlation: Any) -> CorrelationEngine:
        rule = correlation_rule(**correlation)
        definition = parse_correlation(rule.correlation or {}, source="test")
        matchers = build_base_matchers(
            rule, catalog=None, options=DEFAULT_OPTIONS, enforce_logsource=True
        )
        return CorrelationEngine(definition, matchers, source="test")

    def test_a_firing_sequence_passes(self) -> None:
        events = (
            make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}, offset_seconds=0),
            make_event("E2", fields={"Image": "C:\\a\\synthetic.exe"}, offset_seconds=10),
        )
        result = run_sequence(self.engine(), make_sequence(events=events))
        assert result.outcome is Outcome.PASSED

    def test_a_failure_message_counts_the_events(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        result = run_sequence(self.engine(), make_sequence(events=events))
        assert "over 1 events" in result.message

    def test_a_failure_message_names_the_source(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        sequence = make_sequence(events=events, source_path="fixtures/x.jsonl")
        assert "fixtures/x.jsonl" in run_sequence(self.engine(), sequence).message

    def test_the_expected_flag_follows_the_fixture_kind(self) -> None:
        events = (make_event("E1", fields={"Image": "C:\\a\\synthetic.exe"}),)
        sequence = make_sequence(kind=FixtureKind.NEGATIVE, events=events)
        assert run_sequence(self.engine(), sequence).expected_match is False

    def test_an_empty_sequence_does_not_fire(self) -> None:
        result = run_sequence(self.engine(), make_sequence(events=()))
        assert result.actual_match is False


class TestRunCatalog:
    def test_every_rule_is_visited(self) -> None:
        catalog = RuleCatalog([make_rule("a", rule_id="a"), make_rule("b", rule_id="b")])
        summary = run_catalog(catalog, FixtureSet())
        assert {result.catalog_id for result in summary.results} == {"a", "b"}

    def test_the_only_filter_narrows_the_run(self) -> None:
        catalog = RuleCatalog([make_rule("a", rule_id="a"), make_rule("b", rule_id="b")])
        summary = run_catalog(catalog, FixtureSet(), only=["a"])
        assert {result.catalog_id for result in summary.results} == {"a"}

    def test_an_empty_catalog_produces_no_results(self) -> None:
        assert run_catalog(RuleCatalog([]), FixtureSet()).results == ()

    def test_the_summary_records_the_evaluator(self) -> None:
        assert run_catalog(RuleCatalog([]), FixtureSet()).evaluator

    def test_the_summary_is_timestamped(self) -> None:
        assert run_catalog(RuleCatalog([]), FixtureSet()).generated_at.endswith("Z")

    def test_skips_alone_still_count_as_successful(self) -> None:
        summary = run_catalog(RuleCatalog([make_rule()]), FixtureSet())
        assert summary.successful is True

    def test_a_failing_fixture_makes_the_run_unsuccessful(self) -> None:
        fixtures = FixtureSet(cases=(make_case(event=NON_MATCHING_EVENT),))
        summary = run_catalog(RuleCatalog([make_rule(detection=MATCHING_DETECTION)]), fixtures)
        assert summary.successful is False


class TestSummarisation:
    def summary_with(self, *cases: Any) -> Summary:
        fixtures = FixtureSet(cases=tuple(cases))
        return run_catalog(RuleCatalog([make_rule(detection=MATCHING_DETECTION)]), fixtures)

    def test_totals_add_up(self) -> None:
        payload = summarise(self.summary_with(make_case(event=MATCHING_EVENT)))
        totals = payload["totals"]
        assert totals["total"] == sum(
            totals[key] for key in ("passed", "failed", "errored", "skipped", "unsupported")
        )

    def test_the_banner_is_present(self) -> None:
        assert "synthetic" in summarise(Summary()).get("banner", "").lower()

    def test_the_evaluator_is_named(self) -> None:
        assert summarise(Summary())["evaluator"]

    def test_per_rule_counts_are_reported(self) -> None:
        payload = summarise(self.summary_with(make_case(event=MATCHING_EVENT)))
        assert payload["per_rule"]["SDEL-TST-001"]["passed"] == 1

    def test_per_rule_keys_are_sorted(self) -> None:
        catalog = RuleCatalog([make_rule("zulu", rule_id="z"), make_rule("alpha", rule_id="a")])
        payload = summarise(run_catalog(catalog, FixtureSet()))
        assert list(payload["per_rule"]) == sorted(payload["per_rule"])

    def test_an_empty_summary_reports_zero(self) -> None:
        assert summarise(Summary())["totals"]["total"] == 0

    def test_success_is_reported(self) -> None:
        assert summarise(self.summary_with(make_case(event=MATCHING_EVENT)))["successful"] is True


class TestFailingResults:
    def test_passes_are_not_blocking(self) -> None:
        fixtures = FixtureSet(cases=(make_case(event=MATCHING_EVENT),))
        summary = run_catalog(RuleCatalog([make_rule(detection=MATCHING_DETECTION)]), fixtures)
        assert failing_results(summary) == ()

    def test_failures_are_blocking(self) -> None:
        fixtures = FixtureSet(cases=(make_case(event=NON_MATCHING_EVENT),))
        summary = run_catalog(RuleCatalog([make_rule(detection=MATCHING_DETECTION)]), fixtures)
        assert len(failing_results(summary)) == 1

    def test_skips_are_not_blocking(self) -> None:
        summary = run_catalog(RuleCatalog([make_rule()]), FixtureSet())
        assert failing_results(summary) == ()

    def test_unsupported_results_are_blocking(self) -> None:
        rule = make_rule(detection={"selection": {"Image|weird": "x"}, "condition": "selection"})
        fixtures = FixtureSet(cases=(make_case(event=MATCHING_EVENT),))
        summary = run_catalog(RuleCatalog([rule]), fixtures)
        assert len(failing_results(summary)) == 1


class TestRealRun:
    def test_the_real_run_produces_results(self, real_summary: Summary) -> None:
        assert real_summary.total > 0

    def test_the_real_run_has_no_failures(self, real_summary: Summary) -> None:
        assert [result.case_id for result in failing_results(real_summary)] == []

    def test_the_real_run_is_successful(self, real_summary: Summary) -> None:
        assert real_summary.successful is True

    def test_the_real_run_evaluates_most_rules(
        self, real_summary: Summary, real_catalog: RuleCatalog
    ) -> None:
        assert len({result.catalog_id for result in real_summary.results}) == len(real_catalog)

    def test_no_real_rule_is_unsupported(self, real_summary: Summary) -> None:
        assert real_summary.unsupported == 0

    def test_the_summary_serialises(self, real_summary: Summary) -> None:
        assert summarise(real_summary)["totals"]["total"] == real_summary.total
