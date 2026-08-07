"""Structural validation, at both the specification and the lab-subset level."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import make_rule
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.models import FindingCategory, LogSource, Rule
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import pysigma_status
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.sigma_validation import (
    MAX_DESCRIPTION_LENGTH,
    MAX_TITLE_LENGTH,
    MIN_DESCRIPTION_LENGTH,
    structural_summary,
    validate_catalog,
    validate_core_fields,
    validate_correlation,
    validate_dates,
    validate_detection,
    validate_rule,
    validate_with_pysigma,
)

GOOD_DESCRIPTION = "A synthetic rule used by the offline suite to exercise structural checks."


def codes(findings: list[Any]) -> list[str]:
    return [finding.code for finding in findings]


def correlation_rule(
    correlation: dict[str, Any] | None = None,
    *,
    documents: tuple[dict[str, Any], ...] = (),
) -> Rule:
    return make_rule(
        catalog_id="SDEL-COR-001",
        is_correlation=True,
        logsource=LogSource(),
        correlation=correlation
        if correlation is not None
        else {
            "type": "event_count",
            "rules": ["base_events"],
            "group-by": ["host"],
            "timespan": "5m",
            "condition": {"gte": 3},
        },
        documents=documents,
    )


class TestCoreFields:
    def test_a_sound_rule_reports_nothing(self) -> None:
        assert validate_core_fields(make_rule(description=GOOD_DESCRIPTION)) == []

    def test_a_missing_description_is_reported(self) -> None:
        assert codes(validate_core_fields(make_rule(description=""))) == ["SDEL-STR-002"]

    def test_a_missing_description_is_high_severity(self) -> None:
        assert validate_core_fields(make_rule(description=""))[0].severity is Severity.HIGH

    def test_a_short_description_is_reported(self) -> None:
        assert codes(validate_core_fields(make_rule(description="too short"))) == ["SDEL-STR-003"]

    def test_a_description_at_the_minimum_passes(self) -> None:
        rule = make_rule(description="x" * MIN_DESCRIPTION_LENGTH)
        assert codes(validate_core_fields(rule)) == []

    def test_a_description_below_the_minimum_fails(self) -> None:
        rule = make_rule(description="x" * (MIN_DESCRIPTION_LENGTH - 1))
        assert codes(validate_core_fields(rule)) == ["SDEL-STR-003"]

    def test_an_overlong_description_is_reported(self) -> None:
        rule = make_rule(description="x" * (MAX_DESCRIPTION_LENGTH + 1))
        assert codes(validate_core_fields(rule)) == ["SDEL-STR-004"]

    def test_an_overlong_description_is_only_advisory(self) -> None:
        rule = make_rule(description="x" * (MAX_DESCRIPTION_LENGTH + 1))
        assert validate_core_fields(rule)[0].severity is Severity.LOW

    def test_an_overlong_title_is_reported(self) -> None:
        rule = make_rule(title="t" * (MAX_TITLE_LENGTH + 1), description=GOOD_DESCRIPTION)
        assert codes(validate_core_fields(rule)) == ["SDEL-STR-001"]

    def test_a_title_at_the_limit_passes(self) -> None:
        rule = make_rule(title="t" * MAX_TITLE_LENGTH, description=GOOD_DESCRIPTION)
        assert codes(validate_core_fields(rule)) == []

    def test_an_empty_logsource_is_reported(self) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION, logsource=LogSource())
        assert codes(validate_core_fields(rule)) == ["SDEL-STR-005"]

    def test_a_correlation_rule_needs_no_logsource(self) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION, logsource=LogSource(), is_correlation=True)
        assert codes(validate_core_fields(rule)) == []

    def test_a_service_alone_satisfies_the_logsource_check(self) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION, logsource=LogSource(service="auditd"))
        assert codes(validate_core_fields(rule)) == []

    def test_the_logsource_finding_names_its_gate(self) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION, logsource=LogSource())
        assert validate_core_fields(rule)[0].gate == "valid_logsource"

    def test_findings_point_at_the_rule_file(self) -> None:
        rule = make_rule(description="", relative_path="rules/windows/x.yml")
        assert validate_core_fields(rule)[0].path == "rules/windows/x.yml"

    def test_findings_are_categorised_as_structural(self) -> None:
        assert validate_core_fields(make_rule(description=""))[0].category is (
            FindingCategory.STRUCTURE
        )


class TestDates:
    def test_a_sound_date_reports_nothing(self) -> None:
        assert validate_dates(make_rule(date="2026-08-01")) == []

    def test_a_missing_date_is_reported(self) -> None:
        assert codes(validate_dates(make_rule(date=None))) == ["SDEL-STR-020"]

    def test_a_missing_date_suggests_the_format(self) -> None:
        assert "YYYY-MM-DD" in validate_dates(make_rule(date=None))[0].remediation

    @pytest.mark.parametrize("value", ["2026-13-01", "01-08-2026", "2026/08/01", "yesterday"])
    def test_a_malformed_date_is_reported(self, value: str) -> None:
        assert codes(validate_dates(make_rule(date=value))) == ["SDEL-STR-021"]

    def test_a_leap_day_is_accepted(self) -> None:
        assert validate_dates(make_rule(date="2024-02-29")) == []

    def test_a_non_leap_day_is_refused(self) -> None:
        assert codes(validate_dates(make_rule(date="2025-02-29"))) == ["SDEL-STR-021"]

    def test_a_malformed_modified_date_is_reported(self) -> None:
        rule = make_rule(date="2026-08-01", modified="soon")
        assert codes(validate_dates(rule)) == ["SDEL-STR-022"]

    def test_a_modified_date_before_the_authored_date_is_reported(self) -> None:
        rule = make_rule(date="2026-08-01", modified="2026-07-01")
        assert codes(validate_dates(rule)) == ["SDEL-STR-023"]

    def test_an_out_of_order_pair_is_only_a_medium(self) -> None:
        rule = make_rule(date="2026-08-01", modified="2026-07-01")
        assert validate_dates(rule)[0].severity is Severity.MEDIUM

    def test_a_modified_date_equal_to_the_authored_date_is_fine(self) -> None:
        assert validate_dates(make_rule(date="2026-08-01", modified="2026-08-01")) == []

    def test_a_later_modified_date_is_fine(self) -> None:
        assert validate_dates(make_rule(date="2026-08-01", modified="2026-09-01")) == []

    def test_ordering_is_not_checked_when_the_authored_date_is_malformed(self) -> None:
        rule = make_rule(date="nonsense", modified="2020-01-01")
        assert codes(validate_dates(rule)) == ["SDEL-STR-021"]

    def test_every_date_finding_names_its_gate(self) -> None:
        assert all(f.gate == "valid_date" for f in validate_dates(make_rule(date=None)))


class TestDetection:
    def test_a_sound_detection_reports_nothing(self) -> None:
        assert validate_detection(make_rule()) == []

    def test_a_correlation_rule_is_not_checked(self) -> None:
        rule = make_rule(detection={}, is_correlation=True)
        assert validate_detection(rule) == []

    def test_an_empty_detection_is_critical(self) -> None:
        findings = validate_detection(make_rule(detection={}))
        assert codes(findings) == ["SDEL-STR-010"]
        assert findings[0].severity is Severity.CRITICAL

    def test_a_missing_condition_is_critical(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}})
        assert codes(validate_detection(rule)) == ["SDEL-STR-011"]

    def test_an_unsupported_construct_is_reported(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image": "x"}, "condition": "selection | count() > 5"}
        )
        assert codes(validate_detection(rule)) == ["SDEL-STR-012"]

    def test_an_unsupported_construct_suggests_a_correlation_rule(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image": "x"}, "condition": "selection | count() > 5"}
        )
        assert "correlation rule" in validate_detection(rule)[0].remediation

    def test_a_syntactically_invalid_condition_is_critical(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection and"})
        findings = validate_detection(rule)
        assert codes(findings) == ["SDEL-STR-013"]
        assert findings[0].severity is Severity.CRITICAL

    def test_an_unsupported_modifier_is_reported(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image|base64offset": "x"}, "condition": "selection"}
        )
        assert codes(validate_detection(rule)) == ["SDEL-STR-014"]

    def test_an_unsupported_modifier_points_at_the_profile(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image|base64offset": "x"}, "condition": "selection"}
        )
        assert "evaluator-profile.json" in validate_detection(rule)[0].remediation

    def test_an_unreferenced_selection_is_reported(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"Image": "x"},
                "orphan": {"User": "y"},
                "condition": "selection",
            }
        )
        assert codes(validate_detection(rule)) == ["SDEL-STR-016"]

    def test_the_unreferenced_selection_is_named(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"Image": "x"},
                "orphan": {"User": "y"},
                "condition": "selection",
            }
        )
        assert "orphan" in validate_detection(rule)[0].message

    def test_a_selection_referenced_by_a_quantifier_is_not_orphaned(self) -> None:
        rule = make_rule(
            detection={
                "selection_a": {"Image": "x"},
                "selection_b": {"User": "y"},
                "condition": "1 of selection_*",
            }
        )
        assert validate_detection(rule) == []

    def test_a_selection_referenced_by_a_negation_is_not_orphaned(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"Image": "x"},
                "filter": {"User": "y"},
                "condition": "selection and not filter",
            }
        )
        assert validate_detection(rule) == []


class TestCorrelation:
    def test_a_non_correlation_rule_is_skipped(self) -> None:
        assert validate_correlation(make_rule()) == []

    def test_a_correlation_rule_without_a_block_is_skipped(self) -> None:
        assert validate_correlation(make_rule(is_correlation=True)) == []

    def test_an_invalid_block_is_critical(self) -> None:
        rule = correlation_rule({"type": "nonsense", "rules": ["a"], "timespan": "5m"})
        findings = validate_correlation(rule)
        assert codes(findings) == ["SDEL-COR-001"]
        assert findings[0].severity is Severity.CRITICAL

    def test_an_invalid_block_is_categorised_as_correlation(self) -> None:
        rule = correlation_rule({"type": "nonsense", "rules": ["a"], "timespan": "5m"})
        assert validate_correlation(rule)[0].category is FindingCategory.CORRELATION

    def test_an_unresolvable_reference_is_reported(self) -> None:
        assert codes(validate_correlation(correlation_rule())) == ["SDEL-COR-002"]

    def test_an_inline_base_document_resolves(self) -> None:
        rule = correlation_rule(
            documents=(
                {
                    "name": "base_events",
                    "title": "Base",
                    "detection": {"selection": {"Image": "x"}, "condition": "selection"},
                },
            )
        )
        assert validate_correlation(rule) == []

    def test_a_catalog_rule_resolves_the_reference(self) -> None:
        base = make_rule(catalog_id="base", name="base_events")
        rule = correlation_rule()
        assert validate_correlation(rule, catalog=RuleCatalog([base])) == []

    def test_an_unresolvable_reference_names_the_rule(self) -> None:
        assert "base_events" in validate_correlation(correlation_rule())[0].message

    def test_an_unresolvable_reference_suggests_a_fix(self) -> None:
        assert "base rule" in validate_correlation(correlation_rule())[0].remediation

    def test_each_unresolved_reference_gets_its_own_finding(self) -> None:
        rule = correlation_rule(
            {
                "type": "temporal",
                "rules": ["one", "two"],
                "group-by": ["host"],
                "timespan": "5m",
            }
        )
        assert len(validate_correlation(rule)) == 2


class TestPySigma:
    def test_a_rule_without_raw_text_is_skipped(self) -> None:
        assert validate_with_pysigma(make_rule(raw_text="")) == []

    def test_a_valid_rule_passes(self, real_catalog: RuleCatalog) -> None:
        if not pysigma_status().available:
            pytest.skip("pySigma is not installed")
        rule = next(r for r in real_catalog if r.raw_text and not r.is_correlation)
        assert validate_with_pysigma(rule) == []

    def test_an_invalid_rule_is_rejected(self) -> None:
        if not pysigma_status().available:
            pytest.skip("pySigma is not installed")
        rule = make_rule(raw_text="title: broken\nnot-a-sigma-rule: true\n")
        assert codes(validate_with_pysigma(rule)) == ["SDEL-STR-031"]

    def test_a_rejection_is_critical(self) -> None:
        if not pysigma_status().available:
            pytest.skip("pySigma is not installed")
        rule = make_rule(raw_text="title: broken\nnot-a-sigma-rule: true\n")
        assert validate_with_pysigma(rule)[0].severity is Severity.CRITICAL

    def test_the_pysigma_finding_names_its_gate(self) -> None:
        if not pysigma_status().available:
            pytest.skip("pySigma is not installed")
        rule = make_rule(raw_text="title: broken\nnot-a-sigma-rule: true\n")
        assert validate_with_pysigma(rule)[0].gate == "pysigma_parse"


class TestValidateRule:
    def test_a_sound_rule_reports_nothing(self, tiny_config: LabConfig) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION)
        assert validate_rule(rule, config=tiny_config, run_pysigma=False) == []

    def test_findings_from_several_checks_accumulate(self, tiny_config: LabConfig) -> None:
        rule = make_rule(description="", date=None, detection={})
        found = set(codes(validate_rule(rule, config=tiny_config, run_pysigma=False)))
        assert {"SDEL-STR-002", "SDEL-STR-020", "SDEL-STR-010"} <= found

    def test_pysigma_can_be_skipped(self, tiny_config: LabConfig) -> None:
        rule = make_rule(description=GOOD_DESCRIPTION, raw_text="not a sigma rule at all")
        assert validate_rule(rule, config=tiny_config, run_pysigma=False) == []

    def test_a_correlation_reference_is_checked_against_the_catalog(
        self, tiny_config: LabConfig
    ) -> None:
        rule = correlation_rule()
        findings = validate_rule(rule, config=tiny_config, run_pysigma=False)
        assert "SDEL-COR-002" in codes(findings)


class TestValidateCatalog:
    def test_an_empty_catalog_reports_nothing(self, tiny_config: LabConfig) -> None:
        assert validate_catalog(RuleCatalog([]), config=tiny_config, run_pysigma=False) == []

    def test_uniqueness_findings_are_included(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", description=GOOD_DESCRIPTION)] * 2)
        findings = validate_catalog(catalog, config=tiny_config, run_pysigma=False)
        assert "SDEL-CAT-001" in codes(findings)

    def test_every_rule_is_visited(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", description="", rule_id="1"),
                make_rule(catalog_id="b", description="", rule_id="2"),
            ]
        )
        findings = validate_catalog(catalog, config=tiny_config, run_pysigma=False)
        assert len([f for f in findings if f.code == "SDEL-STR-002"]) == 2

    def test_correlation_references_resolve_against_the_whole_catalog(
        self, tiny_config: LabConfig
    ) -> None:
        base = make_rule(
            catalog_id="base",
            name="base_events",
            description=GOOD_DESCRIPTION,
            rule_id="11111111-1111-4111-8111-111111111111",
        )
        catalog = RuleCatalog([base, correlation_rule()])
        findings = validate_catalog(catalog, config=tiny_config, run_pysigma=False)
        assert "SDEL-COR-002" not in codes(findings)


class TestSummary:
    def test_the_rule_count_is_reported(self) -> None:
        assert structural_summary(RuleCatalog([make_rule()]))["rules_examined"] == 1

    def test_the_pysigma_availability_is_reported(self) -> None:
        summary = structural_summary(RuleCatalog([]))
        assert isinstance(summary["pysigma_available"], bool)

    def test_the_pysigma_version_is_reported_when_available(self) -> None:
        summary = structural_summary(RuleCatalog([]))
        if summary["pysigma_available"]:
            assert summary["pysigma_version"]

    def test_the_pysigma_error_is_reported_when_unavailable(self) -> None:
        summary = structural_summary(RuleCatalog([]))
        if not summary["pysigma_available"]:
            assert summary["pysigma_error"]


class TestRealCatalog:
    def test_the_real_catalog_validates_cleanly(
        self, real_catalog: RuleCatalog, real_config: LabConfig
    ) -> None:
        findings = validate_catalog(real_catalog, config=real_config)
        blocking = [f"{f.code} {f.subject}: {f.message}" for f in findings if f.is_error]
        assert blocking == []

    def test_the_real_catalog_has_no_structural_findings_at_all(
        self, real_catalog: RuleCatalog, real_config: LabConfig
    ) -> None:
        findings = validate_catalog(real_catalog, config=real_config)
        assert [f"{f.code} {f.subject}" for f in findings] == []

    def test_every_real_detection_compiles(self, real_catalog: RuleCatalog) -> None:
        offenders = [rule.catalog_id for rule in real_catalog if validate_detection(rule)]
        assert offenders == []

    def test_every_real_correlation_resolves(self, real_catalog: RuleCatalog) -> None:
        offenders = [
            rule.catalog_id
            for rule in real_catalog
            if validate_correlation(rule, catalog=real_catalog)
        ]
        assert offenders == []

    def test_every_real_rule_carries_a_sound_date(self, real_catalog: RuleCatalog) -> None:
        assert [rule.catalog_id for rule in real_catalog if validate_dates(rule)] == []
