"""The standalone HTML report: offline, escaped, and honestly framed."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from tests.conftest import make_case, make_finding, make_sidecar

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.conversion import ConversionSet
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.html_report import STYLESHEET, render_html, write_html
from sigma_detection_engineering_lab.json_report import ReportBundle
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


@pytest.fixture
def bundle(tiny_config: LabConfig, simple_catalog: RuleCatalog) -> ReportBundle:
    return ReportBundle(config=tiny_config, catalog=simple_catalog, command="validate")


@pytest.fixture
def full_bundle(tiny_config: LabConfig, simple_catalog: RuleCatalog) -> ReportBundle:
    return ReportBundle(
        config=tiny_config,
        catalog=simple_catalog,
        metadata=MetadataSet(sidecars=(make_sidecar(),)),
        fixtures=FixtureSet(cases=(make_case(),)),
        findings=(make_finding(severity=Severity.HIGH),),
        test_summary=TestSummary(
            results=(
                TestResult(
                    case_id="c1",
                    catalog_id="SDEL-TST-001",
                    outcome=TestOutcome.PASSED,
                    expected_match=True,
                    actual_match=True,
                ),
                TestResult(
                    case_id="c2",
                    catalog_id="SDEL-TST-001",
                    outcome=TestOutcome.FAILED,
                    expected_match=True,
                    actual_match=False,
                    message="did not match",
                ),
            )
        ),
        coverage=CoverageReport(total_rules=1, rules_with_sidecar=1),
        quality=QualityReport(
            gates=(
                GateResult(gate="no_secrets", passed=True),
                GateResult(gate="sidecar_exists", passed=False, detail="missing"),
                GateResult(gate="optional", passed=False, enabled=False),
            )
        ),
        conversions=ConversionSet(
            results=(
                ConversionResult(
                    catalog_id="SDEL-TST-001",
                    backend="splunk",
                    status=ConversionStatus.CONVERTED,
                    queries=("index=main Image=*",),
                    message="demonstration",
                ),
                ConversionResult(
                    catalog_id="SDEL-TST-002",
                    backend="splunk",
                    status=ConversionStatus.UNSUPPORTED,
                    message="not supported",
                ),
            ),
            handles=(),
        ),
        command="validate --strict",
    )


class TestDocumentStructure:
    def test_the_doctype_is_first(self, bundle: ReportBundle) -> None:
        assert render_html(bundle).startswith("<!DOCTYPE html>")

    def test_the_document_closes(self, bundle: ReportBundle) -> None:
        assert render_html(bundle).rstrip().endswith("</html>")

    def test_the_language_is_declared(self, bundle: ReportBundle) -> None:
        assert '<html lang="en">' in render_html(bundle)

    def test_the_charset_is_declared(self, bundle: ReportBundle) -> None:
        assert '<meta charset="utf-8">' in render_html(bundle)

    def test_a_viewport_is_declared(self, bundle: ReportBundle) -> None:
        assert 'name="viewport"' in render_html(bundle)

    def test_the_referrer_policy_is_set(self, bundle: ReportBundle) -> None:
        assert 'name="referrer" content="no-referrer"' in render_html(bundle)

    def test_indexing_is_discouraged(self, bundle: ReportBundle) -> None:
        assert 'name="robots" content="noindex"' in render_html(bundle)

    def test_the_title_names_the_project(self, bundle: ReportBundle) -> None:
        assert "sdel-test-project report" in render_html(bundle)

    def test_the_stylesheet_is_inlined(self, bundle: ReportBundle) -> None:
        assert STYLESHEET[:40] in render_html(bundle)

    def test_the_version_is_shown(self, bundle: ReportBundle) -> None:
        from sigma_detection_engineering_lab import __version__

        assert __version__ in render_html(bundle)


class TestOfflineGuarantees:
    def test_no_script_tags(self, full_bundle: ReportBundle) -> None:
        assert "<script" not in render_html(full_bundle).lower()

    def test_no_external_stylesheets(self, full_bundle: ReportBundle) -> None:
        assert "<link" not in render_html(full_bundle).lower()

    def test_no_iframes(self, full_bundle: ReportBundle) -> None:
        assert "<iframe" not in render_html(full_bundle).lower()

    def test_no_images_are_fetched(self, full_bundle: ReportBundle) -> None:
        assert "<img" not in render_html(full_bundle).lower()

    def test_no_remote_urls_in_attributes(self, full_bundle: ReportBundle) -> None:
        html = render_html(full_bundle)
        assert re.search(r'(?:src|href)\s*=\s*"https?://', html) is None

    def test_no_inline_event_handlers(self, full_bundle: ReportBundle) -> None:
        assert re.search(r"\son[a-z]+\s*=", render_html(full_bundle)) is None

    def test_the_footer_states_the_offline_guarantee(self, bundle: ReportBundle) -> None:
        assert "generated offline" in render_html(bundle)


class TestHonestFraming:
    def test_the_no_production_claim_is_present(self, bundle: ReportBundle) -> None:
        assert "production" in render_html(bundle).lower()

    def test_the_synthetic_data_banner_is_present(self, bundle: ReportBundle) -> None:
        assert "synthetic" in render_html(bundle).lower()

    def test_the_coverage_caveat_appears_with_coverage(self, full_bundle: ReportBundle) -> None:
        assert "Coverage" in render_html(full_bundle)

    def test_the_conversion_banner_appears_with_conversions(
        self, full_bundle: ReportBundle
    ) -> None:
        html = render_html(full_bundle)
        assert "not production" in html.lower() or "demonstration" in html.lower()

    def test_conversions_are_labelled_as_demonstrations(self, full_bundle: ReportBundle) -> None:
        assert "have not been validated" in render_html(full_bundle)

    def test_efficacy_metrics_are_disclaimed(self, full_bundle: ReportBundle) -> None:
        assert "Deliberately excluded" in render_html(full_bundle)


class TestSections:
    def test_the_findings_section_is_rendered(self, full_bundle: ReportBundle) -> None:
        assert "Findings" in render_html(full_bundle)

    def test_a_finding_message_appears(self, full_bundle: ReportBundle) -> None:
        assert "synthetic finding" in render_html(full_bundle)

    def test_the_tests_section_is_rendered(self, full_bundle: ReportBundle) -> None:
        assert "<h2>Behavioral testing</h2>" in render_html(full_bundle)

    def test_the_tests_section_states_the_unsupported_rule(self, full_bundle: ReportBundle) -> None:
        assert "never counted as a pass" in render_html(full_bundle)

    def test_a_failing_case_is_shown(self, full_bundle: ReportBundle) -> None:
        assert "did not match" in render_html(full_bundle)

    def test_the_coverage_section_is_rendered(self, full_bundle: ReportBundle) -> None:
        assert "<h2>Coverage</h2>" in render_html(full_bundle)

    def test_the_quality_section_is_rendered(self, full_bundle: ReportBundle) -> None:
        assert "<h2>Quality gates</h2>" in render_html(full_bundle)

    def test_a_failing_gate_is_named(self, full_bundle: ReportBundle) -> None:
        assert "sidecar_exists" in render_html(full_bundle)

    def test_a_disabled_gate_is_labelled(self, full_bundle: ReportBundle) -> None:
        assert "disabled" in render_html(full_bundle)

    def test_the_overall_gate_verdict_is_stated(self, full_bundle: ReportBundle) -> None:
        assert "One or more gates failed" in render_html(full_bundle)

    def test_the_conversions_section_is_rendered(self, full_bundle: ReportBundle) -> None:
        assert "<h2>Backend conversions</h2>" in render_html(full_bundle)

    def test_a_converted_query_appears(self, full_bundle: ReportBundle) -> None:
        assert "index=main Image=*" in render_html(full_bundle)

    def test_an_unconverted_rule_is_listed(self, full_bundle: ReportBundle) -> None:
        assert "SDEL-TST-002" in render_html(full_bundle)

    def test_the_environment_section_is_rendered(self, bundle: ReportBundle) -> None:
        assert "Environment" in render_html(bundle)

    def test_absent_sections_are_omitted(self, bundle: ReportBundle) -> None:
        html = render_html(bundle)
        assert "<h2>Quality gates</h2>" not in html
        assert "<h2>Backend conversions</h2>" not in html


class TestEscaping:
    def test_angle_brackets_in_a_finding_are_escaped(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message="<script>alert(1)</script>"),),
        )
        html = render_html(report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_ampersands_are_escaped(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message="a & b"),),
        )
        assert "a &amp; b" in render_html(report)

    def test_quotes_in_a_subject_are_escaped(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(subject='say "hi"'),),
        )
        assert 'say "hi"' not in render_html(report)

    def test_a_query_containing_markup_is_escaped(self, bundle: ReportBundle) -> None:
        conversions = ConversionSet(
            results=(
                ConversionResult(
                    catalog_id="A",
                    backend="splunk",
                    status=ConversionStatus.CONVERTED,
                    queries=("<b>not markup</b>",),
                ),
            )
        )
        html = render_html(
            ReportBundle(config=bundle.config, catalog=bundle.catalog, conversions=conversions)
        )
        assert "<b>not markup</b>" not in html


class TestRedaction:
    def test_a_credential_in_a_finding_is_redacted(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message=f"key={AWS_KEY}"),),
        )
        assert AWS_KEY not in render_html(report)

    def test_redaction_can_be_disabled_deliberately(self, bundle: ReportBundle) -> None:
        report = ReportBundle(
            config=bundle.config,
            catalog=bundle.catalog,
            findings=(make_finding(message=f"key={AWS_KEY}"),),
        )
        assert AWS_KEY in render_html(report, redact=False)


class TestWriting:
    def test_the_file_is_created(self, bundle: ReportBundle, tmp_path: Path) -> None:
        assert write_html(bundle, tmp_path / "report.html").is_file()

    def test_parent_directories_are_created(self, bundle: ReportBundle, tmp_path: Path) -> None:
        assert write_html(bundle, tmp_path / "a" / "b" / "report.html").parent.is_dir()

    def test_line_endings_are_lf(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_html(bundle, tmp_path / "report.html")
        assert b"\r\n" not in target.read_bytes()

    def test_the_file_is_utf8(self, bundle: ReportBundle, tmp_path: Path) -> None:
        target = write_html(bundle, tmp_path / "report.html")
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE")

    def test_rendering_is_deterministic(self, full_bundle: ReportBundle) -> None:
        assert render_html(full_bundle) == render_html(full_bundle)

    def test_the_written_file_matches_the_rendered_text(
        self, bundle: ReportBundle, tmp_path: Path
    ) -> None:
        target = write_html(bundle, tmp_path / "report.html")
        assert target.read_text(encoding="utf-8") == render_html(bundle)


class TestRealReport:
    def test_a_real_bundle_renders(self, real_config: LabConfig, real_catalog: RuleCatalog) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog, command="validate")
        assert "<!DOCTYPE html>" in render_html(bundle)

    def test_a_real_report_stays_offline(
        self, real_config: LabConfig, real_catalog: RuleCatalog
    ) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog)
        html = render_html(bundle)
        assert "<script" not in html.lower()
        assert re.search(r'(?:src|href)\s*=\s*"https?://', html) is None

    def test_a_real_report_writes_to_a_temporary_path(
        self, real_config: LabConfig, real_catalog: RuleCatalog, tmp_path: Path
    ) -> None:
        bundle = ReportBundle(config=real_config, catalog=real_catalog)
        assert write_html(bundle, tmp_path / "real.html").stat().st_size > 1000
