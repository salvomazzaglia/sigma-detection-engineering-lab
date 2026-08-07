"""Catalog identity, uniqueness, lookup, and filtering."""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

import pytest

from conftest import make_rule
from sigma_detection_engineering_lab.models import LogSource, Rule
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog, RuleFilter, build_catalog
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import SigmaStatus


def rule(catalog_id: str = "sdel-win-001", **overrides: object) -> Rule:
    """Build a rule whose UUID is unique per catalog id unless one is supplied."""
    overrides.setdefault("rule_id", uuid5(NAMESPACE_URL, catalog_id).urn.removeprefix("urn:uuid:"))
    return make_rule(catalog_id=catalog_id, **overrides)  # type: ignore[arg-type]


class TestConstruction:
    def test_an_empty_catalog_has_no_rules(self) -> None:
        assert len(RuleCatalog([])) == 0

    def test_rules_are_sorted_by_catalog_id(self) -> None:
        catalog = RuleCatalog([rule("z-rule"), rule("a-rule"), rule("m-rule")])
        assert catalog.catalog_ids == ("a-rule", "m-rule", "z-rule")

    def test_iteration_yields_the_sorted_rules(self) -> None:
        catalog = RuleCatalog([rule("b"), rule("a")])
        assert [r.catalog_id for r in catalog] == ["a", "b"]

    def test_the_length_is_the_rule_count(self) -> None:
        assert len(RuleCatalog([rule("a"), rule("b"), rule("c")])) == 3

    def test_membership_uses_the_catalog_id(self) -> None:
        catalog = RuleCatalog([rule("a")])
        assert "a" in catalog
        assert "b" not in catalog

    def test_membership_of_a_non_string_is_false(self) -> None:
        assert 7 not in RuleCatalog([rule("a")])

    def test_the_rules_property_is_a_tuple(self) -> None:
        assert isinstance(RuleCatalog([rule()]).rules, tuple)

    def test_the_convenience_constructor_builds_the_same_thing(self) -> None:
        rules = [rule("a"), rule("b")]
        assert build_catalog(rules).catalog_ids == RuleCatalog(rules).catalog_ids


class TestLookup:
    @pytest.fixture
    def catalog(self) -> RuleCatalog:
        return RuleCatalog(
            [
                rule("first", rule_id="11111111-1111-4111-8111-111111111111", name="first_base"),
                rule("second", rule_id="22222222-2222-4222-8222-222222222222"),
            ]
        )

    def test_get_finds_a_rule(self, catalog: RuleCatalog) -> None:
        assert catalog.get("first").catalog_id == "first"

    def test_get_returns_none_for_an_unknown_id(self, catalog: RuleCatalog) -> None:
        assert catalog.get("missing") is None

    def test_lookup_by_uuid(self, catalog: RuleCatalog) -> None:
        found = catalog.by_uuid("11111111-1111-4111-8111-111111111111")
        assert found.catalog_id == "first"

    def test_uuid_lookup_ignores_case(self, catalog: RuleCatalog) -> None:
        assert catalog.by_uuid("22222222-2222-4222-8222-222222222222".upper()) is not None

    def test_uuid_lookup_ignores_surrounding_space(self, catalog: RuleCatalog) -> None:
        assert catalog.by_uuid("  11111111-1111-4111-8111-111111111111 ") is not None

    def test_lookup_by_name(self, catalog: RuleCatalog) -> None:
        assert catalog.by_name("first_base").catalog_id == "first"

    def test_name_lookup_ignores_case(self, catalog: RuleCatalog) -> None:
        assert catalog.by_name("FIRST_BASE") is not None

    def test_resolve_accepts_a_catalog_id(self, catalog: RuleCatalog) -> None:
        assert catalog.resolve("second").catalog_id == "second"

    def test_resolve_accepts_a_uuid(self, catalog: RuleCatalog) -> None:
        assert catalog.resolve("22222222-2222-4222-8222-222222222222").catalog_id == "second"

    def test_resolve_accepts_a_name(self, catalog: RuleCatalog) -> None:
        assert catalog.resolve("first_base").catalog_id == "first"

    def test_resolve_of_an_empty_string_is_none(self, catalog: RuleCatalog) -> None:
        assert catalog.resolve("   ") is None

    def test_resolve_of_an_unknown_reference_is_none(self, catalog: RuleCatalog) -> None:
        assert catalog.resolve("nope") is None

    def test_a_rule_without_a_uuid_is_not_indexed_by_uuid(self) -> None:
        assert RuleCatalog([rule("a", rule_id="")]).by_uuid("") is None

    def test_a_base_document_name_is_indexed(self) -> None:
        target = rule("corr", documents=({"name": "base_events", "title": "t"},))
        assert RuleCatalog([target]).by_name("base_events").catalog_id == "corr"


class TestUniqueness:
    def test_a_unique_catalog_reports_nothing(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("b")])
        assert catalog.uniqueness_findings() == ()

    def test_a_duplicate_catalog_id_is_reported(self) -> None:
        catalog = RuleCatalog(
            [
                rule("a", relative_path="x.yml"),
                rule("a", relative_path="y.yml", rule_id="99999999-9999-4999-8999-999999999999"),
            ]
        )
        codes = [f.code for f in catalog.uniqueness_findings()]
        assert codes == ["SDEL-CAT-001"]

    def test_a_duplicate_catalog_id_is_critical(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("a")])
        assert catalog.uniqueness_findings()[0].severity is Severity.CRITICAL

    def test_a_duplicate_catalog_id_names_both_files(self) -> None:
        catalog = RuleCatalog(
            [rule("a", relative_path="one.yml"), rule("a", relative_path="two.yml")]
        )
        message = catalog.uniqueness_findings()[0].message
        assert "one.yml" in message and "two.yml" in message

    def test_a_duplicate_uuid_is_reported(self) -> None:
        shared = "33333333-3333-4333-8333-333333333333"
        catalog = RuleCatalog([rule("a", rule_id=shared), rule("b", rule_id=shared)])
        assert [f.code for f in catalog.uniqueness_findings()] == ["SDEL-CAT-002"]

    def test_a_duplicate_uuid_is_case_insensitive(self) -> None:
        shared = "44444444-4444-4444-8444-444444444444"
        catalog = RuleCatalog([rule("a", rule_id=shared), rule("b", rule_id=shared.upper())])
        assert len(catalog.uniqueness_findings()) == 1

    def test_a_duplicate_uuid_suggests_a_fresh_uuid(self) -> None:
        shared = "55555555-5555-4555-8555-555555555555"
        catalog = RuleCatalog([rule("a", rule_id=shared), rule("b", rule_id=shared)])
        assert "UUIDv4" in catalog.uniqueness_findings()[0].remediation

    def test_both_kinds_of_duplicate_can_be_reported_together(self) -> None:
        shared = "66666666-6666-4666-8666-666666666666"
        catalog = RuleCatalog(
            [rule("a", rule_id=shared), rule("a", rule_id=shared), rule("a", rule_id=shared)]
        )
        codes = {f.code for f in catalog.uniqueness_findings()}
        assert codes == {"SDEL-CAT-001", "SDEL-CAT-002"}

    def test_duplicate_findings_carry_a_gate_name(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("a")])
        assert catalog.uniqueness_findings()[0].gate == "unique_catalog_id"

    def test_the_first_occurrence_wins_the_index(self) -> None:
        catalog = RuleCatalog(
            [rule("a", relative_path="first.yml"), rule("a", relative_path="second.yml")]
        )
        assert catalog.get("a").relative_path == "first.yml"


class TestFiltering:
    @pytest.fixture
    def catalog(self) -> RuleCatalog:
        return RuleCatalog(
            [
                rule(
                    "win-stable",
                    title="Suspicious Process",
                    status=SigmaStatus.STABLE,
                    level=Severity.HIGH,
                    logsource=LogSource(product="windows", category="process_creation"),
                    tags=("attack.t1059.001", "attack.execution"),
                ),
                rule(
                    "linux-test",
                    title="Odd Shell",
                    status=SigmaStatus.TEST,
                    level=Severity.MEDIUM,
                    logsource=LogSource(product="linux", service="auditd"),
                    tags=("attack.t1059.004",),
                ),
                rule(
                    "corr-rule",
                    title="Burst",
                    status=SigmaStatus.EXPERIMENTAL,
                    level=Severity.LOW,
                    logsource=LogSource(),
                    tags=(),
                    is_correlation=True,
                ),
            ]
        )

    def test_no_criteria_returns_everything(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter()) == 3

    def test_filter_by_status(self, catalog: RuleCatalog) -> None:
        found = catalog.filter(status=SigmaStatus.STABLE)
        assert [r.catalog_id for r in found] == ["win-stable"]

    def test_filter_by_level(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(level=Severity.MEDIUM)] == ["linux-test"]

    def test_filter_by_product(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(product="windows")] == ["win-stable"]

    def test_product_matching_ignores_case(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(product="WINDOWS")) == 1

    def test_filter_by_category(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(category="process_creation")) == 1

    def test_filter_by_service(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(service="auditd")] == ["linux-test"]

    def test_a_rule_without_the_field_never_matches_it(self, catalog: RuleCatalog) -> None:
        assert "corr-rule" not in [r.catalog_id for r in catalog.filter(product="windows")]

    def test_filter_by_technique(self, catalog: RuleCatalog) -> None:
        found = catalog.filter(technique="t1059.001")
        assert [r.catalog_id for r in found] == ["win-stable"]

    def test_technique_matching_ignores_case(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(technique="T1059.001")) == 1

    def test_filter_by_raw_tag(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(tag="attack.execution")) == 1

    def test_filter_by_correlation_true(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(correlation=True)] == ["corr-rule"]

    def test_filter_by_correlation_false(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(correlation=False)) == 2

    def test_free_text_matches_the_title(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(text="suspicious")] == ["win-stable"]

    def test_free_text_matches_the_catalog_id(self, catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in catalog.filter(text="corr-")] == ["corr-rule"]

    def test_free_text_matches_a_tag(self, catalog: RuleCatalog) -> None:
        assert len(catalog.filter(text="t1059.004")) == 1

    def test_free_text_that_matches_nothing_returns_empty(self, catalog: RuleCatalog) -> None:
        assert catalog.filter(text="zzzz") == ()

    def test_criteria_combine_with_and(self, catalog: RuleCatalog) -> None:
        assert catalog.filter(product="windows", level=Severity.MEDIUM) == ()

    def test_a_prebuilt_filter_can_be_passed(self, catalog: RuleCatalog) -> None:
        criteria = RuleFilter(status=SigmaStatus.TEST)
        assert [r.catalog_id for r in catalog.filter(criteria)] == ["linux-test"]

    def test_an_explicit_filter_wins_over_keywords(self, catalog: RuleCatalog) -> None:
        criteria = RuleFilter(status=SigmaStatus.TEST)
        assert len(catalog.filter(criteria, product="windows")) == 1

    def test_the_filter_is_hashable(self) -> None:
        assert {RuleFilter(product="windows"), RuleFilter(product="windows")}.__len__() == 1


class TestPartitions:
    def test_standard_rules_exclude_correlations(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("b", is_correlation=True)])
        assert [r.catalog_id for r in catalog.standard_rules()] == ["a"]

    def test_correlation_rules_are_selected(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("b", is_correlation=True)])
        assert [r.catalog_id for r in catalog.correlation_rules()] == ["b"]

    def test_the_partitions_are_disjoint_and_complete(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("b", is_correlation=True), rule("c")])
        assert len(catalog.standard_rules()) + len(catalog.correlation_rules()) == len(catalog)

    def test_grouping_by_logsource(self) -> None:
        catalog = RuleCatalog(
            [
                rule("a", logsource=LogSource(product="windows", category="process_creation")),
                rule("b", logsource=LogSource(product="windows", category="process_creation")),
                rule("c", logsource=LogSource(product="linux")),
            ]
        )
        grouped = catalog.group_by_logsource()
        assert sum(len(v) for v in grouped.values()) == 3
        assert len(grouped) == 2

    def test_logsource_groups_are_sorted(self) -> None:
        catalog = RuleCatalog(
            [
                rule("a", logsource=LogSource(product="windows")),
                rule("b", logsource=LogSource(product="linux")),
            ]
        )
        assert list(catalog.group_by_logsource()) == sorted(catalog.group_by_logsource())


class TestSummary:
    def test_the_total_is_reported(self) -> None:
        assert RuleCatalog([rule("a"), rule("b")]).summary()["total"] == 2

    def test_standard_and_correlation_counts_are_reported(self) -> None:
        summary = RuleCatalog([rule("a"), rule("b", is_correlation=True)]).summary()
        assert (summary["standard"], summary["correlation"]) == (1, 1)

    def test_statuses_are_counted(self) -> None:
        catalog = RuleCatalog(
            [rule("a", status=SigmaStatus.STABLE), rule("b", status=SigmaStatus.STABLE)]
        )
        assert catalog.summary()["by_status"]["stable"] == 2

    def test_levels_are_counted(self) -> None:
        catalog = RuleCatalog([rule("a", level=Severity.HIGH)])
        assert catalog.summary()["by_level"]["high"] == 1

    def test_status_counts_are_sorted(self) -> None:
        catalog = RuleCatalog(
            [rule("a", status=SigmaStatus.TEST), rule("b", status=SigmaStatus.EXPERIMENTAL)]
        )
        keys = list(catalog.summary()["by_status"])
        assert keys == sorted(keys)

    def test_the_logsource_count_is_reported(self) -> None:
        catalog = RuleCatalog(
            [rule("a", logsource=LogSource(product="windows")), rule("b", logsource=LogSource())]
        )
        assert catalog.summary()["logsources"] == 2

    def test_duplicate_counts_are_reported(self) -> None:
        catalog = RuleCatalog([rule("a"), rule("a")])
        assert catalog.summary()["duplicate_catalog_ids"] == 1

    def test_an_empty_catalog_summarises_to_zeroes(self) -> None:
        summary = RuleCatalog([]).summary()
        assert summary["total"] == 0
        assert summary["by_status"] == {}

    def test_to_dict_carries_the_summary_and_the_rules(self) -> None:
        payload = RuleCatalog([rule("a")]).to_dict()
        assert payload["summary"]["total"] == 1
        assert len(payload["rules"]) == 1

    def test_to_dict_rules_are_serialisable_mappings(self) -> None:
        payload = RuleCatalog([rule("a")]).to_dict()
        assert payload["rules"][0]["catalog_id"] == "a"


class TestRealCatalog:
    def test_the_real_catalog_loads_rules(self, real_catalog: RuleCatalog) -> None:
        assert len(real_catalog) >= 50

    def test_the_real_catalog_has_no_duplicates(self, real_catalog: RuleCatalog) -> None:
        assert real_catalog.uniqueness_findings() == ()

    def test_every_real_rule_resolves_by_its_own_id(self, real_catalog: RuleCatalog) -> None:
        assert all(real_catalog.resolve(r.catalog_id) is r for r in real_catalog)

    def test_every_real_rule_resolves_by_uuid(self, real_catalog: RuleCatalog) -> None:
        assert all(real_catalog.by_uuid(r.rule_id) is not None for r in real_catalog if r.rule_id)

    def test_the_real_catalog_contains_correlation_rules(self, real_catalog: RuleCatalog) -> None:
        assert real_catalog.correlation_rules()

    def test_the_real_summary_totals_agree(self, real_catalog: RuleCatalog) -> None:
        summary = real_catalog.summary()
        assert summary["standard"] + summary["correlation"] == summary["total"]
