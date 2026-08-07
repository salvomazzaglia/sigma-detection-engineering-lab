"""Coverage metrics, and the efficacy metrics deliberately absent from them."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from conftest import make_case, make_rule, make_sequence, make_sidecar
from sigma_detection_engineering_lab.attack_catalog import AttackCatalog
from sigma_detection_engineering_lab.constants import COVERAGE_CAVEAT_BANNER
from sigma_detection_engineering_lab.coverage import (
    EXCLUDED_METRICS,
    FixtureBalance,
    build_coverage,
    coverage_payload,
    fixture_balance,
    rule_has_fixtures,
    rule_is_fully_tested,
    summarise_rules,
    technique_gaps,
)
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    AttackMapping,
    FixtureKind,
    LogSource,
    TestOutcome,
    TestResult,
    TestSummary,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

EMPTY_FIXTURES = FixtureSet(cases=(), sequences=())
EMPTY_METADATA = MetadataSet(sidecars=())


def outcome(catalog_id: str, value: TestOutcome, case_id: str = "c1") -> TestResult:
    return TestResult(
        case_id=case_id,
        catalog_id=catalog_id,
        outcome=value,
        expected_match=True,
        actual_match=value is TestOutcome.PASSED,
        duration_seconds=0.0,
    )


class TestFullyTested:
    def test_no_summary_means_not_tested(self) -> None:
        assert rule_is_fully_tested("a", None) is False

    def test_no_results_for_the_rule_means_not_tested(self) -> None:
        assert rule_is_fully_tested("a", TestSummary(results=())) is False

    def test_all_passing_means_fully_tested(self) -> None:
        summary = TestSummary(results=(outcome("a", TestOutcome.PASSED),))
        assert rule_is_fully_tested("a", summary) is True

    @pytest.mark.parametrize(
        "value",
        [TestOutcome.FAILED, TestOutcome.ERROR, TestOutcome.SKIPPED, TestOutcome.UNSUPPORTED],
    )
    def test_any_non_passing_outcome_disqualifies(self, value: TestOutcome) -> None:
        summary = TestSummary(results=(outcome("a", TestOutcome.PASSED), outcome("a", value, "c2")))
        assert rule_is_fully_tested("a", summary) is False

    def test_another_rules_results_do_not_count(self) -> None:
        summary = TestSummary(results=(outcome("b", TestOutcome.PASSED),))
        assert rule_is_fully_tested("a", summary) is False


class TestHasFixtures:
    def test_no_fixtures_is_false(self) -> None:
        assert rule_has_fixtures("a", EMPTY_FIXTURES) is False

    def test_a_case_counts(self) -> None:
        fixtures = FixtureSet(cases=(make_case(catalog_id="a"),), sequences=())
        assert rule_has_fixtures("a", fixtures) is True

    def test_a_sequence_counts(self) -> None:
        fixtures = FixtureSet(cases=(), sequences=(make_sequence(catalog_id="a"),))
        assert rule_has_fixtures("a", fixtures) is True

    def test_another_rules_fixtures_do_not_count(self) -> None:
        fixtures = FixtureSet(cases=(make_case(catalog_id="b"),), sequences=())
        assert rule_has_fixtures("a", fixtures) is False


class TestBuildCoverage:
    def test_an_empty_catalog_reports_zero(self) -> None:
        report = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        assert report.total_rules == 0

    def test_the_rule_total_is_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a"), make_rule(catalog_id="b")])
        report = build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES)
        assert report.total_rules == 2

    def test_a_rule_without_a_sidecar_is_unmapped(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        report = build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES)
        assert report.unmapped_rules == ("a",)

    def test_a_sidecar_is_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(sidecars=(make_sidecar(catalog_id="a"),))
        assert build_coverage(catalog, metadata, EMPTY_FIXTURES).rules_with_sidecar == 1

    def test_an_attack_mapping_is_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(sidecars=(make_sidecar(catalog_id="a"),))
        assert build_coverage(catalog, metadata, EMPTY_FIXTURES).rules_with_attack_mapping == 1

    def test_an_empty_mapping_leaves_the_rule_unmapped(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(
            sidecars=(make_sidecar(catalog_id="a", attack_mapping=AttackMapping()),)
        )
        assert build_coverage(catalog, metadata, EMPTY_FIXTURES).unmapped_rules == ("a",)

    def test_techniques_are_counted_and_upper_cased(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(
            sidecars=(
                make_sidecar(catalog_id="a", attack_mapping=AttackMapping(techniques=("t1059",))),
            )
        )
        assert build_coverage(catalog, metadata, EMPTY_FIXTURES).technique_counts == {"T1059": 1}

    def test_tactics_are_counted_and_lower_cased(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(
            sidecars=(
                make_sidecar(
                    catalog_id="a",
                    attack_mapping=AttackMapping(techniques=("T1"), tactics=("TA0002",)),
                ),
            )
        )
        assert "ta0002" in build_coverage(catalog, metadata, EMPTY_FIXTURES).tactic_counts

    def test_the_same_technique_across_rules_accumulates(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", rule_id="11111111-1111-4111-8111-111111111111"),
                make_rule(catalog_id="b", rule_id="22222222-2222-4222-8222-222222222222"),
            ]
        )
        metadata = MetadataSet(
            sidecars=tuple(
                make_sidecar(name, attack_mapping=AttackMapping(techniques=("T1059",)))
                for name in ("a", "b")
            )
        )
        assert build_coverage(catalog, metadata, EMPTY_FIXTURES).technique_counts["T1059"] == 2

    def test_logsources_are_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", logsource=LogSource(product="windows"))])
        assert build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).logsource_counts

    def test_levels_are_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", level=Severity.HIGH)])
        assert build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).level_counts["high"] == 1

    def test_statuses_are_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        assert (
            sum(build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).status_counts.values()) == 1
        )

    def test_maturities_are_counted_only_for_sidecars(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        assert build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).maturity_counts == {}

    def test_fixtures_are_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        fixtures = FixtureSet(cases=(make_case(catalog_id="a"),), sequences=())
        assert build_coverage(catalog, EMPTY_METADATA, fixtures).rules_with_fixtures == 1

    def test_a_fully_tested_rule_is_counted(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        summary = TestSummary(results=(outcome("a", TestOutcome.PASSED),))
        assert (
            build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES, summary).rules_fully_tested == 1
        )

    def test_an_untested_rule_is_listed(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        assert build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).untested_rules == ("a",)

    def test_untested_rules_are_sorted(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="z", rule_id="11111111-1111-4111-8111-111111111111"),
                make_rule(catalog_id="a", rule_id="22222222-2222-4222-8222-222222222222"),
            ]
        )
        report = build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES)
        assert report.untested_rules == ("a", "z")

    def test_counts_are_sorted_by_key(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", level=Severity.HIGH),
                make_rule(
                    catalog_id="b",
                    level=Severity.CRITICAL,
                    rule_id="22222222-2222-4222-8222-222222222222",
                ),
            ]
        )
        keys = list(build_coverage(catalog, EMPTY_METADATA, EMPTY_FIXTURES).level_counts)
        assert keys == sorted(keys)

    def test_a_timestamp_is_recorded(self) -> None:
        report = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        assert report.generated_at.endswith("Z")


class TestFixtureBalance:
    def test_a_rule_with_no_fixtures_reports_zeroes(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        balance = fixture_balance(catalog, EMPTY_FIXTURES)[0]
        assert (balance.positive_events, balance.negative_events) == (0, 0)

    def test_positive_and_negative_cases_are_separated(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        fixtures = FixtureSet(
            cases=(
                make_case(catalog_id="a", kind=FixtureKind.POSITIVE),
                make_case(catalog_id="a", kind=FixtureKind.NEGATIVE, case_id="n1"),
                make_case(catalog_id="a", kind=FixtureKind.NEGATIVE, case_id="n2"),
            ),
            sequences=(),
        )
        balance = fixture_balance(catalog, fixtures)[0]
        assert (balance.positive_events, balance.negative_events) == (1, 2)

    def test_sequences_are_counted_separately(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", is_correlation=True)])
        fixtures = FixtureSet(
            cases=(),
            sequences=(make_sequence(catalog_id="a", kind=FixtureKind.POSITIVE),),
        )
        assert fixture_balance(catalog, fixtures)[0].positive_sequences == 1

    def test_the_correlation_flag_is_carried(self) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", is_correlation=True)])
        assert fixture_balance(catalog, EMPTY_FIXTURES)[0].is_correlation is True

    def test_one_balance_per_rule(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", rule_id="11111111-1111-4111-8111-111111111111"),
                make_rule(catalog_id="b", rule_id="22222222-2222-4222-8222-222222222222"),
            ]
        )
        assert len(fixture_balance(catalog, EMPTY_FIXTURES)) == 2

    def test_a_balance_serialises(self) -> None:
        balance = FixtureBalance("a", False, 1, 2, 0, 0)
        assert balance.to_dict()["negative_events"] == 2

    def test_a_balance_is_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            FixtureBalance("a", False, 0, 0, 0, 0).catalog_id = "b"  # type: ignore[misc]


class TestTechniqueGaps:
    def test_an_unavailable_catalog_yields_no_gaps(self) -> None:
        coverage = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        assert technique_gaps(coverage, AttackCatalog()) == ()

    def test_an_unmapped_catalog_technique_is_a_gap(self, real_attack: AttackCatalog) -> None:
        coverage = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        assert technique_gaps(coverage, real_attack)

    def test_gaps_respect_the_limit(self, real_attack: AttackCatalog) -> None:
        coverage = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        assert len(technique_gaps(coverage, real_attack, limit=3)) <= 3

    def test_gaps_are_sorted(self, real_attack: AttackCatalog) -> None:
        coverage = build_coverage(RuleCatalog([]), EMPTY_METADATA, EMPTY_FIXTURES)
        gaps = technique_gaps(coverage, real_attack, limit=10)
        assert list(gaps) == sorted(gaps)

    def test_a_mapped_technique_is_not_a_gap(self, real_attack: AttackCatalog) -> None:
        target = sorted(real_attack.techniques)[0]
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(
            sidecars=(
                make_sidecar(catalog_id="a", attack_mapping=AttackMapping(techniques=(target,))),
            )
        )
        coverage = build_coverage(catalog, metadata, EMPTY_FIXTURES)
        assert target not in technique_gaps(coverage, real_attack, limit=1000)

    def test_gap_matching_ignores_case(self, real_attack: AttackCatalog) -> None:
        target = sorted(real_attack.techniques)[0]
        catalog = RuleCatalog([make_rule(catalog_id="a")])
        metadata = MetadataSet(
            sidecars=(
                make_sidecar(
                    catalog_id="a", attack_mapping=AttackMapping(techniques=(target.lower(),))
                ),
            )
        )
        coverage = build_coverage(catalog, metadata, EMPTY_FIXTURES)
        assert target not in technique_gaps(coverage, real_attack, limit=1000)


class TestPayload:
    @pytest.fixture
    def coverage(self):  # type: ignore[no-untyped-def]
        return build_coverage(
            RuleCatalog([make_rule(catalog_id="a")]), EMPTY_METADATA, EMPTY_FIXTURES
        )

    def test_the_caveat_banner_is_present(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert coverage_payload(coverage)["banner"] == COVERAGE_CAVEAT_BANNER

    def test_the_excluded_metrics_are_named(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert coverage_payload(coverage)["excluded_metrics"] == list(EXCLUDED_METRICS)

    @pytest.mark.parametrize("metric", EXCLUDED_METRICS)
    def test_no_excluded_metric_is_reported_as_a_value(
        self,
        coverage,  # type: ignore[no-untyped-def]
        metric: str,
    ) -> None:
        payload = coverage_payload(coverage)
        assert metric not in {key for key in payload if key != "excluded_metrics"}

    def test_the_exclusion_is_explained(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert coverage_payload(coverage)["excluded_metrics_note"]

    def test_the_report_fields_are_merged_in(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert coverage_payload(coverage)["total_rules"] == 1

    def test_attack_details_are_optional(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert "attack_version" not in coverage_payload(coverage)

    def test_attack_details_are_included_when_given(
        self,
        coverage,  # type: ignore[no-untyped-def]
        real_attack: AttackCatalog,
    ) -> None:
        payload = coverage_payload(coverage, attack=real_attack)
        assert payload["attack_catalog_available"] is True

    def test_gaps_are_included_with_the_attack_catalog(
        self,
        coverage,  # type: ignore[no-untyped-def]
        real_attack: AttackCatalog,
    ) -> None:
        assert "unmapped_catalog_techniques" in coverage_payload(coverage, attack=real_attack)

    def test_balances_are_optional(self, coverage) -> None:  # type: ignore[no-untyped-def]
        assert "fixture_balance" not in coverage_payload(coverage)

    def test_balances_are_included_when_given(self, coverage) -> None:  # type: ignore[no-untyped-def]
        balances = (FixtureBalance("a", False, 1, 1, 0, 0),)
        payload = coverage_payload(coverage, balances=balances)
        assert payload["fixture_balance"][0]["catalog_id"] == "a"


class TestSummariseRules:
    def test_an_empty_selection_counts_zero(self) -> None:
        assert summarise_rules([])["count"] == 0

    def test_the_count_is_reported(self) -> None:
        assert summarise_rules([make_rule(), make_rule()])["count"] == 2

    def test_correlation_rules_are_counted(self) -> None:
        rules = [make_rule(), make_rule(is_correlation=True)]
        assert summarise_rules(rules)["correlation"] == 1

    def test_levels_are_broken_down(self) -> None:
        rules = [make_rule(level=Severity.HIGH), make_rule(level=Severity.HIGH)]
        assert summarise_rules(rules)["levels"] == {"high": 2}

    def test_the_level_breakdown_is_sorted(self) -> None:
        rules = [make_rule(level=Severity.LOW), make_rule(level=Severity.CRITICAL)]
        keys = list(summarise_rules(rules)["levels"])
        assert keys == sorted(keys)


class TestRealCoverage:
    def test_the_real_catalog_is_fully_documented(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet, real_fixtures: FixtureSet
    ) -> None:
        report = build_coverage(real_catalog, real_metadata, real_fixtures)
        assert report.rules_with_sidecar == report.total_rules

    def test_every_real_rule_is_mapped(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet, real_fixtures: FixtureSet
    ) -> None:
        report = build_coverage(real_catalog, real_metadata, real_fixtures)
        assert report.unmapped_rules == ()

    def test_every_real_rule_has_fixtures(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet, real_fixtures: FixtureSet
    ) -> None:
        report = build_coverage(real_catalog, real_metadata, real_fixtures)
        assert report.rules_with_fixtures == report.total_rules

    def test_the_real_behavioral_run_leaves_no_untested_rule(
        self,
        real_catalog: RuleCatalog,
        real_metadata: MetadataSet,
        real_fixtures: FixtureSet,
        real_summary: TestSummary,
    ) -> None:
        report = build_coverage(real_catalog, real_metadata, real_fixtures, real_summary)
        assert report.untested_rules == ()

    def test_the_real_payload_carries_the_caveat(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet, real_fixtures: FixtureSet
    ) -> None:
        report = build_coverage(real_catalog, real_metadata, real_fixtures)
        assert COVERAGE_CAVEAT_BANNER in coverage_payload(report)["banner"]
