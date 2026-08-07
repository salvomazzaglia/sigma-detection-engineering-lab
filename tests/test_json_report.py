"""The canonical JSON report and the bundle every other writer consumes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import make_case, make_finding, make_sidecar

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.conversion import ConversionSet
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.json_report import (
    SCHEMA_ID,
    ReportBundle,
    build_report,
    findings_to_csv,
    render_json,
    write_document,
    write_json_report,
)
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    ConversionResult,
    ConversionStatus,
    CoverageReport,
    GateResult,
    QualityReport,
    TestOutcome,
    TestResult,
    TestSummary,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def summary_with(outcome: TestOutcome = TestOutcome.PASSED) -> TestSummary:
    return TestSummary(
        results=(
            TestResult(
                case_id="c1",
                catalog_id="SDEL-TST-001",
                outcome=outcome,
                expected_match=True,
                actual_match=outcome is TestOutcome.PASSED,
            ),
        )
    )


@pytest.fixture
def bundle(tiny_config: LabConfig, simple_catalog: RuleCatalog) -> ReportBundle:
    return ReportBundle(config=tiny_config, catalog=simple_catalog, command="validate")


class TestBundlePassSemantics:
    def test_an_empty_bundle_passes(self, bundle: ReportBundle) -> None:
        assert bundle.passed is True

    def test_a_critical_finding_fails_the_bundle(self, bundle: ReportBundle) -> None:
        failing = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(severity=Severity.CRITICAL),),
        )
        assert failing.passed is False

    def test_a_low_finding_does_not_fail_the_bundle(self, bundle: ReportBundle) -> None:
        passing = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(severity=Severity.LOW),),
        )
        assert passing.passed is True

    def test_a_load_failure_fails_the_bundle(self, bundle: ReportBundle) -> None:
        failing = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, load_failures=(("a.yml", "boom"),)
        )
        assert failing.passed is False

    def test_a_failing_test_summary_fails_the_bundle(self, bundle: ReportBundle) -> None:
        failing = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            test_summary=summary_with(TestOutcome.FAILED),
        )
        assert failing.passed is False

    def test_a_passing_test_summary_keeps_the_bundle_green(self, bundle: ReportBundle) -> None:
        passing = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, test_summary=summary_with()
        )
        assert passing.passed is True

    def test_a_failing_quality_report_fails_the_bundle(self, bundle: ReportBundle) -> None:
        quality = QualityReport(gates=(GateResult(gate="no_secrets", passed=False),))
        failing = ReportBundle(config=bundle.config, catalog=bundle.catalog, quality=quality)
        assert failing.passed is False

    def test_a_stage_that_did_not_run_cannot_fail_the_bundle(self, bundle: ReportBundle) -> None:
        assert bundle.test_summary is None
        assert bundle.passed is True

    def test_the_validation_view_counts_examined_rules(self, bundle: ReportBundle) -> None:
        assert bundle.validation.rules_examined == len(bundle.catalog)

    def test_the_validation_view_carries_the_findings(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, findings=(make_finding(),)
        )
        assert len(report.validation.findings) == 1


class TestDocumentShape:
    def test_the_schema_identifier_is_declared(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["schema"] == SCHEMA_ID

    def test_production_readiness_is_denied(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["production_ready"] is False

    def test_a_disclaimer_is_present(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["disclaimer"]

    def test_every_banner_is_present(self, bundle: ReportBundle) -> None:
        banners = build_report(bundle)["banners"]
        assert {"synthetic_data", "synthetic_testing", "conversion", "coverage", "all"} <= set(
            banners
        )

    def test_the_banner_list_is_not_empty(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["banners"]["all"]

    def test_the_command_is_recorded(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["command"] == "validate"

    def test_the_document_is_timestamped(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["generated_at"].endswith("Z")

    def test_the_environment_reports_the_tool_version(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["environment"]["tool_version"]

    def test_the_environment_reports_pysigma_availability(self, bundle: ReportBundle) -> None:
        assert isinstance(build_report(bundle)["environment"]["pysigma_available"], bool)

    def test_the_project_block_names_the_project(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["project"]["name"] == "sdel-test-project"

    def test_the_project_block_lists_authors(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["project"]["authors"] == ["Salvatore Mazzaglia"]

    def test_the_catalog_summary_is_included(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["catalog"]["total"] == 1

    def test_the_validation_section_is_always_present(self, bundle: ReportBundle) -> None:
        assert "validation" in build_report(bundle)

    def test_the_pass_flag_mirrors_the_bundle(self, bundle: ReportBundle) -> None:
        assert build_report(bundle)["passed"] == bundle.passed


class TestOptionalSections:
    def test_absent_sections_are_omitted(self, bundle: ReportBundle) -> None:
        document = build_report(bundle)
        assert not {"tests", "coverage", "quality", "conversions"} & set(document)

    def test_load_failures_appear_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, load_failures=(("a.yml", "boom"),)
        )
        assert build_report(report)["load_failures"][0]["path"] == "a.yml"

    def test_metadata_appears_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            metadata=MetadataSet(sidecars=(make_sidecar(),)),
        )
        assert build_report(report)["metadata"]["sidecar_count"] == 1

    def test_fixtures_appear_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            fixtures=FixtureSet(cases=(make_case(),)),
        )
        assert build_report(report)["fixtures"]["case_count"] == 1

    def test_tests_appear_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, test_summary=summary_with()
        )
        assert build_report(report)["tests"]["totals"]["total"] == 1

    def test_the_test_section_carries_the_banner(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, test_summary=summary_with()
        )
        assert build_report(report)["tests"]["banner"]

    def test_test_totals_add_up(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, test_summary=summary_with()
        )
        totals = build_report(report)["tests"]["totals"]
        assert totals["total"] == sum(
            totals[key] for key in ("passed", "failed", "errored", "skipped", "unsupported")
        )

    def test_coverage_appears_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, coverage=CoverageReport()
        )
        assert "coverage" in build_report(report)

    def test_coverage_carries_the_excluded_metrics_note(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, coverage=CoverageReport()
        )
        assert build_report(report)["coverage"]["excluded_metrics_note"]

    def test_quality_appears_when_present(self, bundle: ReportBundle) -> None:
        report = ReportBundle(config=bundle.config, catalog=bundle.catalog, quality=QualityReport())
        assert "quality" in build_report(report)

    def test_conversions_appear_when_present(self, bundle: ReportBundle) -> None:
        conversions = ConversionSet(
            results=(
                ConversionResult(
                    catalog_id="A", backend="splunk", status=ConversionStatus.CONVERTED
                ),
            )
        )
        report = ReportBundle(config=bundle.config, catalog=bundle.catalog, conversions=conversions)
        assert build_report(report)["conversions"]["production_ready"] is False

    def test_the_telemetry_summary_appears_when_present(
        self, bundle: ReportBundle, tiny_config: LabConfig
    ) -> None:
        from sigma_detection_engineering_lab.telemetry import load_telemetry_catalog

        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            telemetry=load_telemetry_catalog(tiny_config),
        )
        assert build_report(report)["telemetry_catalog"]["available"] is True


class TestRedactionInReports:
    def test_findings_are_redacted_by_default(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message=f"saw key={AWS_KEY}"),),
        )
        assert AWS_KEY not in json.dumps(build_report(report))

    def test_redaction_can_be_disabled_deliberately(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message=f"saw key={AWS_KEY}"),),
        )
        assert AWS_KEY in json.dumps(build_report(report, redact=False))

    def test_the_whole_document_is_walked(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, command=f"validate --token={AWS_KEY}"
        )
        assert AWS_KEY not in json.dumps(build_report(report))


class TestRendering:
    def test_the_output_parses_as_json(self, bundle: ReportBundle) -> None:
        assert json.loads(render_json(bundle))["schema"] == SCHEMA_ID

    def test_keys_are_sorted(self, bundle: ReportBundle) -> None:
        text = render_json(bundle)
        assert text.index('"banners"') < text.index('"catalog"')

    def test_the_output_ends_with_a_newline(self, bundle: ReportBundle) -> None:
        assert render_json(bundle).endswith("\n")

    def test_rendering_is_deterministic(self, bundle: ReportBundle) -> None:
        assert render_json(bundle) == render_json(bundle)

    def test_the_indent_is_configurable(self, bundle: ReportBundle) -> None:
        assert "\n    " in render_json(bundle, indent=4)

    def test_non_ascii_survives(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config, catalog=bundle.catalog, command="validate --note=café"
        )
        assert "café" in render_json(report)


class TestWriting:
    def test_the_file_is_created(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_json_report(bundle, tmp_path / "out" / "report.json")
        assert target.is_file()

    def test_parent_directories_are_created(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_json_report(bundle, tmp_path / "a" / "b" / "report.json")
        assert target.parent.is_dir()

    def test_line_endings_are_lf(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_json_report(bundle, tmp_path / "report.json")
        assert b"\r\n" not in target.read_bytes()

    def test_the_written_file_parses(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_json_report(bundle, tmp_path / "report.json")
        assert json.loads(target.read_text(encoding="utf-8"))["schema"] == SCHEMA_ID

    def test_an_arbitrary_document_can_be_written(self, tmp_path: Path) -> None:
        target = write_document({"b": 1, "a": 2}, tmp_path / "doc.json")
        assert json.loads(target.read_text(encoding="utf-8")) == {"a": 2, "b": 1}

    def test_an_arbitrary_document_is_key_sorted(self, tmp_path: Path) -> None:
        target = write_document({"b": 1, "a": 2}, tmp_path / "doc.json")
        text = target.read_text(encoding="utf-8")
        assert text.index('"a"') < text.index('"b"')

    def test_an_arbitrary_document_ends_with_a_newline(self, tmp_path: Path) -> None:
        target = write_document([1, 2], tmp_path / "doc.json")
        assert target.read_text(encoding="utf-8").endswith("\n")

    def test_writing_overwrites_cleanly(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        write_document({"padding": "x" * 500}, target)
        write_json_report(bundle, target)
        assert json.loads(target.read_text(encoding="utf-8"))["schema"] == SCHEMA_ID


class TestFindingsCsv:
    def test_the_header_names_every_column(self) -> None:
        header = findings_to_csv([]).splitlines()[0]
        assert header == "code,severity,category,subject,path,gate,message,remediation"

    def test_an_empty_list_produces_only_a_header(self) -> None:
        assert len(findings_to_csv([]).splitlines()) == 1

    def test_one_finding_produces_one_row(self) -> None:
        assert len(findings_to_csv([make_finding()]).splitlines()) == 2

    def test_the_code_is_the_first_column(self) -> None:
        row = findings_to_csv([make_finding(code="SDEL-X-001")]).splitlines()[1]
        assert row.startswith("SDEL-X-001,")

    def test_absent_optional_fields_become_empty_cells(self) -> None:
        row = findings_to_csv([make_finding(gate=None, remediation=None)]).splitlines()[1]
        assert row.endswith(",")

    def test_commas_in_a_message_are_quoted(self) -> None:
        row = findings_to_csv([make_finding(message="a, b, c")]).splitlines()[1]
        assert '"a, b, c"' in row

    def test_secrets_are_redacted(self) -> None:
        text = findings_to_csv([make_finding(message=f"key={AWS_KEY}")])
        assert AWS_KEY not in text

    def test_line_endings_are_lf(self) -> None:
        assert "\r\n" not in findings_to_csv([make_finding()])


class TestRealBundle:
    def test_a_real_bundle_renders(self, real_config: LabConfig, real_catalog: RuleCatalog) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog, command="validate")
        assert json.loads(render_json(bundle))["catalog"]["total"] == len(real_catalog)

    def test_a_real_bundle_never_claims_production_readiness(
        self, real_config: LabConfig, real_catalog: RuleCatalog
    ) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog)
        assert build_report(bundle)["production_ready"] is False

    def test_a_real_bundle_writes_to_a_temporary_path(
        self, real_config: LabConfig, real_catalog: RuleCatalog, tmp_path: Path
    ) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog)
        assert write_json_report(bundle, tmp_path / "real.json").stat().st_size > 0
