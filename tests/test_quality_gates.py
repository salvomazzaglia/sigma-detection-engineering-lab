"""Quality gates, and the rule that an unproven outcome never passes."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from conftest import make_case, make_finding, make_rule, make_sequence, make_sidecar, write_json
from sigma_detection_engineering_lab.config import BackendConfig, LabConfig
from sigma_detection_engineering_lab.conversion import BackendHandle, ConversionSet
from sigma_detection_engineering_lab.errors import ConfigError
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    ConversionResult,
    ConversionStatus,
    FixtureKind,
    Maturity,
    TestOutcome,
    TestResult,
    TestSummary,
)
from sigma_detection_engineering_lab.quality_gates import (
    COMPUTED_GATES,
    GATES_FILENAME,
    LIST_GATES,
    THRESHOLD_GATES,
    GateInputs,
    QualityGateConfig,
    apply_gates,
    gate_summary,
    load_quality_gates,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

EMPTY_FIXTURES = FixtureSet(cases=(), sequences=())
EMPTY_METADATA = MetadataSet(sidecars=())


def inputs(config: LabConfig, **overrides: Any) -> GateInputs:
    base: dict[str, Any] = {
        "config": config,
        "catalog": RuleCatalog([make_rule(catalog_id="a")]),
        "metadata": EMPTY_METADATA,
        "fixtures": EMPTY_FIXTURES,
    }
    base.update(overrides)
    return GateInputs(**base)


def gates(**values: Any) -> QualityGateConfig:
    return QualityGateConfig(gates=dict(values))


def backend_settings(key: str = "splunk") -> BackendConfig:
    return BackendConfig(
        key=key,
        enabled=True,
        package="pysigma-backend-splunk",
        version="1.1.0",
        backend_class="sigma.backends.splunk.SplunkBackend",
        dialect="spl",
        demonstration_banner="Demonstration only; not validated against a live SIEM.",
    )


def result_of(report: Any, name: str) -> Any:
    return next(gate for gate in report.gates if gate.gate == name)


def behavioral_result(
    outcome: TestOutcome = TestOutcome.PASSED,
    *,
    expected_match: bool = True,
    catalog_id: str = "a",
    case_id: str = "c1",
) -> TestResult:
    return TestResult(
        case_id=case_id,
        catalog_id=catalog_id,
        outcome=outcome,
        expected_match=expected_match,
        actual_match=expected_match if outcome is TestOutcome.PASSED else not expected_match,
        duration_seconds=0.0,
    )


class TestGateConfig:
    def test_a_true_gate_is_enabled(self) -> None:
        assert gates(a=True).is_enabled("a") is True

    def test_a_false_gate_is_disabled(self) -> None:
        assert gates(a=False).is_enabled("a") is False

    def test_an_absent_gate_is_disabled(self) -> None:
        assert gates().is_enabled("a") is False

    def test_a_non_boolean_value_counts_as_enabled(self) -> None:
        assert gates(a=3).is_enabled("a") is True

    def test_a_threshold_is_read(self) -> None:
        assert gates(a=3).threshold("a") == 3

    def test_an_absent_threshold_uses_the_default(self) -> None:
        assert gates().threshold("a", 7) == 7

    def test_a_boolean_is_not_a_threshold(self) -> None:
        assert gates(a=True).threshold("a", 5) == 5

    def test_a_string_is_not_a_threshold(self) -> None:
        assert gates(a="3").threshold("a", 5) == 5

    def test_a_list_gate_is_read(self) -> None:
        assert gates(a=["x", "y"]).allowed_list("a") == ("x", "y")

    def test_a_string_is_not_a_list_gate(self) -> None:
        assert gates(a="xy").allowed_list("a") == ()

    def test_an_absent_list_gate_is_empty(self) -> None:
        assert gates().allowed_list("a") == ()

    def test_boolean_gate_names_are_reported(self) -> None:
        assert gates(a=True, b=3, c=False).boolean_gate_names() == ("a", "c")

    def test_to_dict_carries_the_gates(self) -> None:
        assert gates(a=True).to_dict()["gates"] == {"a": True}

    def test_to_dict_carries_the_banned_falsepositives(self) -> None:
        config = QualityGateConfig(falsepositive_banned_exact=("unknown",))
        assert config.to_dict()["falsepositive_banned_exact"] == ["unknown"]

    def test_the_config_is_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            gates().notes = "x"  # type: ignore[misc]


class TestLoading:
    def test_the_real_gates_load(self, real_config: LabConfig) -> None:
        assert load_quality_gates(real_config).gates

    def test_an_absent_file_yields_an_empty_config(self, tiny_config: LabConfig) -> None:
        target = tiny_config.config_dir / GATES_FILENAME
        if target.exists():
            target.unlink()
        assert load_quality_gates(tiny_config).gates == {}

    def test_an_empty_config_produces_no_gates(self, tiny_config: LabConfig) -> None:
        target = tiny_config.config_dir / GATES_FILENAME
        if target.exists():
            target.unlink()
        report = apply_gates(inputs(tiny_config), load_quality_gates(tiny_config))
        assert report.gates == ()

    def test_a_file_without_a_gates_block_keeps_the_schema_version(
        self, tiny_config: LabConfig
    ) -> None:
        write_json(tiny_config.config_dir / GATES_FILENAME, {"schema_version": "2.0"})
        assert load_quality_gates(tiny_config).schema_version == "2.0"

    def test_a_non_object_gates_block_is_refused(self, tiny_config: LabConfig) -> None:
        write_json(tiny_config.config_dir / GATES_FILENAME, {"gates": ["a"]})
        with pytest.raises(ConfigError, match="must be an object"):
            load_quality_gates(tiny_config)

    def test_a_non_list_banned_block_is_refused(self, tiny_config: LabConfig) -> None:
        write_json(
            tiny_config.config_dir / GATES_FILENAME,
            {"gates": {}, "falsepositive_banned_exact": "unknown"},
        )
        with pytest.raises(ConfigError, match="must be a list"):
            load_quality_gates(tiny_config)

    def test_the_banned_list_is_loaded(self, tiny_config: LabConfig) -> None:
        write_json(
            tiny_config.config_dir / GATES_FILENAME,
            {"gates": {}, "falsepositive_banned_exact": ["Unknown"]},
        )
        assert load_quality_gates(tiny_config).falsepositive_banned_exact == ("Unknown",)

    def test_notes_are_loaded(self, tiny_config: LabConfig) -> None:
        write_json(tiny_config.config_dir / GATES_FILENAME, {"gates": {}, "notes": "why"})
        assert load_quality_gates(tiny_config).notes == "why"


class TestFindingDrivenGates:
    def test_a_gate_with_no_findings_passes(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True))
        assert result_of(report, "no_secrets").passed is True

    def test_a_blocking_finding_fails_the_gate(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.HIGH)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert result_of(report, "no_secrets").passed is False

    def test_an_advisory_finding_does_not_fail_the_gate(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.LOW)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert result_of(report, "no_secrets").passed is True

    def test_an_advisory_finding_is_still_attached(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.LOW)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert result_of(report, "no_secrets").findings == (finding,)

    def test_a_finding_for_another_gate_is_ignored(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="other", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert result_of(report, "no_secrets").passed is True

    def test_an_untagged_finding_is_ignored(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate=None, severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert result_of(report, "no_secrets").passed is True

    def test_a_disabled_gate_passes_without_being_enforced(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=False))
        gate = result_of(report, "no_secrets")
        assert (gate.passed, gate.enabled) == (True, False)

    def test_an_unrecognised_value_is_not_enforced(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets="yes"))
        assert result_of(report, "no_secrets").enabled is False

    def test_gates_are_evaluated_in_sorted_order(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(zebra=True, alpha=True))
        assert [gate.gate for gate in report.gates] == ["alpha", "zebra"]


class TestSafeYamlLoadGate:
    def test_a_clean_load_passes(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(safe_yaml_load=True))
        assert result_of(report, "safe_yaml_load").passed is True

    def test_a_load_failure_fails_the_gate(self, tiny_config: LabConfig) -> None:
        failures = (("rules/bad.yml", "unsafe tag"),)
        report = apply_gates(
            inputs(tiny_config, load_failures=failures), gates(safe_yaml_load=True)
        )
        assert result_of(report, "safe_yaml_load").passed is False

    def test_the_failure_is_reported_as_critical(self, tiny_config: LabConfig) -> None:
        failures = (("rules/bad.yml", "unsafe tag"),)
        report = apply_gates(
            inputs(tiny_config, load_failures=failures), gates(safe_yaml_load=True)
        )
        assert result_of(report, "safe_yaml_load").findings[0].severity is Severity.CRITICAL

    def test_an_empty_catalog_cannot_demonstrate_the_gate(self, tiny_config: LabConfig) -> None:
        report = apply_gates(
            inputs(tiny_config, catalog=RuleCatalog([])), gates(safe_yaml_load=True)
        )
        gate = result_of(report, "safe_yaml_load")
        assert gate.passed is False
        assert "could not be demonstrated" in gate.detail


class TestFixtureMinimumGates:
    def test_a_zero_threshold_enforces_nothing(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(minimum_positive_fixtures_standard=0))
        assert result_of(report, "minimum_positive_fixtures_standard").passed is True

    def test_a_rule_below_the_minimum_fails(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(minimum_positive_fixtures_standard=1))
        assert result_of(report, "minimum_positive_fixtures_standard").passed is False

    def test_a_rule_at_the_minimum_passes(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(catalog_id="a"),), sequences=())
        report = apply_gates(
            inputs(tiny_config, fixtures=fixtures), gates(minimum_positive_fixtures_standard=1)
        )
        assert result_of(report, "minimum_positive_fixtures_standard").passed is True

    def test_the_finding_names_the_shortfall(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(minimum_positive_fixtures_standard=2))
        message = result_of(report, "minimum_positive_fixtures_standard").findings[0].message
        assert "requires at least 2" in message

    def test_negative_fixtures_have_their_own_gate(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(
            cases=(make_case(catalog_id="a", kind=FixtureKind.NEGATIVE),), sequences=()
        )
        report = apply_gates(
            inputs(tiny_config, fixtures=fixtures), gates(minimum_negative_fixtures_standard=1)
        )
        assert result_of(report, "minimum_negative_fixtures_standard").passed is True

    def test_standard_gates_skip_correlation_rules(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", is_correlation=True)])
        report = apply_gates(
            inputs(tiny_config, catalog=catalog), gates(minimum_positive_fixtures_standard=1)
        )
        assert result_of(report, "minimum_positive_fixtures_standard").passed is True

    def test_correlation_gates_skip_standard_rules(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(minimum_positive_sequences_correlation=1))
        assert result_of(report, "minimum_positive_sequences_correlation").passed is True

    def test_a_correlation_rule_without_sequences_fails(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", is_correlation=True)])
        report = apply_gates(
            inputs(tiny_config, catalog=catalog),
            gates(minimum_positive_sequences_correlation=1),
        )
        assert result_of(report, "minimum_positive_sequences_correlation").passed is False

    def test_a_correlation_rule_with_sequences_passes(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule(catalog_id="a", is_correlation=True)])
        fixtures = FixtureSet(cases=(), sequences=(make_sequence(catalog_id="a"),))
        report = apply_gates(
            inputs(tiny_config, catalog=catalog, fixtures=fixtures),
            gates(minimum_positive_sequences_correlation=1),
        )
        assert result_of(report, "minimum_positive_sequences_correlation").passed is True

    @pytest.mark.parametrize("name", THRESHOLD_GATES)
    def test_every_threshold_gate_is_recognised(self, tiny_config: LabConfig, name: str) -> None:
        report = apply_gates(inputs(tiny_config), gates(**{name: 0}))
        assert result_of(report, name).enabled is True


class TestExpectationGates:
    def test_without_tests_the_gate_is_unproven(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(all_positive_must_match=True))
        gate = result_of(report, "all_positive_must_match")
        assert gate.passed is False
        assert "unproven" in gate.detail

    def test_a_passing_positive_case_passes_the_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        assert result_of(report, "all_positive_must_match").passed is True

    def test_a_failing_positive_case_fails_the_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.FAILED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        assert result_of(report, "all_positive_must_match").passed is False

    def test_an_errored_positive_case_fails_the_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.ERROR),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        assert result_of(report, "all_positive_must_match").passed is False

    def test_no_positive_cases_leaves_the_gate_unproven(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(expected_match=False),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        assert result_of(report, "all_positive_must_match").passed is False

    def test_negative_cases_have_their_own_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(expected_match=False),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_negative_must_reject=True)
        )
        assert result_of(report, "all_negative_must_reject").passed is True

    def test_a_failing_negative_case_fails_its_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(
            results=(behavioral_result(TestOutcome.FAILED, expected_match=False),)
        )
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_negative_must_reject=True)
        )
        assert result_of(report, "all_negative_must_reject").passed is False

    def test_an_unsupported_case_is_not_counted_as_a_positive_pass(
        self, tiny_config: LabConfig
    ) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.UNSUPPORTED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        gate = result_of(report, "all_positive_must_match")
        assert gate.passed is False
        assert "no positive cases were executed" in gate.detail

    def test_the_failure_finding_names_the_case(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.FAILED, case_id="the-case"),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary), gates(all_positive_must_match=True)
        )
        assert "the-case" in result_of(report, "all_positive_must_match").findings[0].message


class TestUnsupportedGate:
    def test_without_tests_the_gate_is_unproven(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(unsupported_not_counted_as_pass=True))
        assert result_of(report, "unsupported_not_counted_as_pass").passed is False

    def test_a_definite_run_passes(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary),
            gates(unsupported_not_counted_as_pass=True),
        )
        assert result_of(report, "unsupported_not_counted_as_pass").passed is True

    def test_an_unsupported_result_fails_the_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.UNSUPPORTED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary),
            gates(unsupported_not_counted_as_pass=True),
        )
        assert result_of(report, "unsupported_not_counted_as_pass").passed is False

    def test_a_skipped_result_fails_the_gate(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.SKIPPED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary),
            gates(unsupported_not_counted_as_pass=True),
        )
        assert result_of(report, "unsupported_not_counted_as_pass").passed is False

    def test_an_unsupported_result_is_high_severity(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.UNSUPPORTED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary),
            gates(unsupported_not_counted_as_pass=True),
        )
        assert result_of(report, "unsupported_not_counted_as_pass").findings[0].severity is (
            Severity.HIGH
        )

    def test_a_skipped_result_is_medium_severity(self, tiny_config: LabConfig) -> None:
        summary = TestSummary(results=(behavioral_result(TestOutcome.SKIPPED),))
        report = apply_gates(
            inputs(tiny_config, test_summary=summary),
            gates(unsupported_not_counted_as_pass=True),
        )
        assert result_of(report, "unsupported_not_counted_as_pass").findings[0].severity is (
            Severity.MEDIUM
        )


class TestConversionGate:
    def converted(self, banner: str = "demonstration only") -> ConversionSet:
        result = ConversionResult(
            catalog_id="a",
            backend="splunk",
            status=ConversionStatus.CONVERTED,
            queries=("index=main",),
            banner=banner,
        )
        handle = BackendHandle(key="splunk", settings=backend_settings(), available=True)
        return ConversionSet(results=(result,), handles=(handle,))

    def test_no_attempt_fails_the_gate(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(conversion_status_recorded=True))
        assert result_of(report, "conversion_status_recorded").passed is False

    def test_an_empty_result_set_fails_the_gate(self, tiny_config: LabConfig) -> None:
        report = apply_gates(
            inputs(tiny_config, conversions=ConversionSet(results=(), handles=())),
            gates(conversion_status_recorded=True),
        )
        assert result_of(report, "conversion_status_recorded").passed is False

    def test_a_recorded_conversion_passes(self, tiny_config: LabConfig) -> None:
        report = apply_gates(
            inputs(tiny_config, conversions=self.converted()),
            gates(conversion_status_recorded=True),
        )
        assert result_of(report, "conversion_status_recorded").passed is True

    def test_a_missing_banner_fails_the_gate(self, tiny_config: LabConfig) -> None:
        report = apply_gates(
            inputs(tiny_config, conversions=self.converted(banner="   ")),
            gates(conversion_status_recorded=True),
        )
        assert result_of(report, "conversion_status_recorded").passed is False

    def test_the_missing_banner_finding_names_the_backend(self, tiny_config: LabConfig) -> None:
        report = apply_gates(
            inputs(tiny_config, conversions=self.converted(banner="")),
            gates(conversion_status_recorded=True),
        )
        assert "splunk" in result_of(report, "conversion_status_recorded").findings[0].message

    def test_no_available_backend_fails_the_gate(self, tiny_config: LabConfig) -> None:
        result = ConversionResult(
            catalog_id="a",
            backend="splunk",
            status=ConversionStatus.BACKEND_UNAVAILABLE,
            banner="demonstration only",
        )
        handle = BackendHandle(
            key="splunk",
            settings=backend_settings(),
            available=False,
            error="package missing",
        )
        conversions = ConversionSet(results=(result,), handles=(handle,))
        report = apply_gates(
            inputs(tiny_config, conversions=conversions), gates(conversion_status_recorded=True)
        )
        gate = result_of(report, "conversion_status_recorded")
        assert gate.passed is False
        assert "no backend was available" in gate.detail

    def test_the_unavailable_finding_carries_the_reason(self, tiny_config: LabConfig) -> None:
        result = ConversionResult(
            catalog_id="a",
            backend="splunk",
            status=ConversionStatus.BACKEND_UNAVAILABLE,
            banner="demonstration only",
        )
        handle = BackendHandle(
            key="splunk",
            settings=backend_settings(),
            available=False,
            error="package missing",
        )
        conversions = ConversionSet(results=(result,), handles=(handle,))
        report = apply_gates(
            inputs(tiny_config, conversions=conversions), gates(conversion_status_recorded=True)
        )
        assert (
            "package missing" in result_of(report, "conversion_status_recorded").findings[0].message
        )


class TestMaturityGate:
    def test_no_restriction_passes(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(maturity_allowed=[]))
        assert result_of(report, "maturity_allowed").passed is True

    def test_an_allowed_maturity_passes(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(maturity=Maturity.EXPERIMENTAL),))
        report = apply_gates(
            inputs(tiny_config, metadata=metadata), gates(maturity_allowed=["experimental"])
        )
        assert result_of(report, "maturity_allowed").passed is True

    def test_a_disallowed_maturity_fails(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(maturity=Maturity.PRODUCTION_OBSERVED),))
        report = apply_gates(
            inputs(tiny_config, metadata=metadata), gates(maturity_allowed=["experimental"])
        )
        assert result_of(report, "maturity_allowed").passed is False

    def test_the_finding_names_the_allowed_set(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(maturity=Maturity.PRODUCTION_OBSERVED),))
        report = apply_gates(
            inputs(tiny_config, metadata=metadata), gates(maturity_allowed=["experimental"])
        )
        assert "experimental" in result_of(report, "maturity_allowed").findings[0].message

    def test_matching_ignores_case(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(maturity=Maturity.EXPERIMENTAL),))
        report = apply_gates(
            inputs(tiny_config, metadata=metadata), gates(maturity_allowed=["EXPERIMENTAL"])
        )
        assert result_of(report, "maturity_allowed").passed is True

    def test_the_maturity_gate_is_a_list_gate(self) -> None:
        assert "maturity_allowed" in LIST_GATES


class TestReportShape:
    def test_the_report_counts_the_rules_examined(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True))
        assert report.rules_examined == 1

    def test_the_report_is_timestamped(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True))
        assert report.generated_at.endswith("Z")

    def test_the_report_passes_when_every_gate_passes(self, tiny_config: LabConfig) -> None:
        assert apply_gates(inputs(tiny_config), gates(no_secrets=True)).passed is True

    def test_one_failing_gate_fails_the_report(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert report.passed is False

    def test_failed_gates_are_listed(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert [gate.gate for gate in report.failed_gates] == ["no_secrets"]

    def test_every_gate_carries_a_detail_line(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True, safe_yaml_load=True))
        assert all(gate.detail for gate in report.gates)

    def test_the_summary_reports_the_verdict(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True))
        assert gate_summary(report)["passed"] is True

    def test_the_summary_counts_enabled_gates(self, tiny_config: LabConfig) -> None:
        report = apply_gates(inputs(tiny_config), gates(no_secrets=True, other=False))
        summary = gate_summary(report)
        assert (summary["total_gates"], summary["enabled_gates"]) == (2, 1)

    def test_the_summary_lists_failures(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert gate_summary(report)["failed_gates"] == ["no_secrets"]

    def test_the_summary_counts_findings(self, tiny_config: LabConfig) -> None:
        finding = make_finding(gate="no_secrets", severity=Severity.CRITICAL)
        report = apply_gates(inputs(tiny_config, findings=(finding,)), gates(no_secrets=True))
        assert gate_summary(report)["finding_count"] == 1


class TestGateInputs:
    def test_findings_are_selected_by_gate(self, tiny_config: LabConfig) -> None:
        wanted = make_finding(gate="a")
        other = make_finding(gate="b")
        assert inputs(tiny_config, findings=(wanted, other)).findings_for_gate("a") == (wanted,)

    def test_no_findings_yields_an_empty_tuple(self, tiny_config: LabConfig) -> None:
        assert inputs(tiny_config).findings_for_gate("a") == ()

    def test_the_inputs_are_frozen(self, tiny_config: LabConfig) -> None:
        with pytest.raises(FrozenInstanceError):
            inputs(tiny_config).findings = ()  # type: ignore[misc]

    def test_computed_gates_cover_the_threshold_and_list_gates(self) -> None:
        assert set(THRESHOLD_GATES) | set(LIST_GATES) <= COMPUTED_GATES


class TestRealGates:
    def test_the_real_gate_file_defines_gates(self, real_config: LabConfig) -> None:
        assert len(load_quality_gates(real_config).gates) >= 5

    def test_every_computed_gate_name_is_known_to_the_evaluator(
        self, real_config: LabConfig
    ) -> None:
        configured = set(load_quality_gates(real_config).gates)
        assert COMPUTED_GATES & configured

    def test_the_real_gates_evaluate_without_error(
        self,
        real_config: LabConfig,
        real_catalog: RuleCatalog,
        real_metadata: MetadataSet,
        real_fixtures: FixtureSet,
        real_summary: TestSummary,
    ) -> None:
        report = apply_gates(
            GateInputs(
                config=real_config,
                catalog=real_catalog,
                metadata=real_metadata,
                fixtures=real_fixtures,
                test_summary=real_summary,
            ),
            load_quality_gates(real_config),
        )
        assert report.gates

    def test_the_real_behavioral_gates_pass(
        self,
        real_config: LabConfig,
        real_catalog: RuleCatalog,
        real_metadata: MetadataSet,
        real_fixtures: FixtureSet,
        real_summary: TestSummary,
    ) -> None:
        report = apply_gates(
            GateInputs(
                config=real_config,
                catalog=real_catalog,
                metadata=real_metadata,
                fixtures=real_fixtures,
                test_summary=real_summary,
            ),
            load_quality_gates(real_config),
        )
        behavioral = {
            "all_positive_must_match",
            "all_negative_must_reject",
            "unsupported_not_counted_as_pass",
            "safe_yaml_load",
        }
        failed = {gate.gate for gate in report.failed_gates} & behavioral
        assert failed == set()
