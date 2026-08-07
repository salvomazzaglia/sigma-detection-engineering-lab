"""JUnit XML output, where an unsupported rule cannot reach a green build."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest

from sigma_detection_engineering_lab.junit_report import SUITE_NAME, render_junit, write_junit
from sigma_detection_engineering_lab.models import TestOutcome, TestResult, TestSummary


def result(
    outcome: TestOutcome = TestOutcome.PASSED,
    *,
    case_id: str = "case-1",
    catalog_id: str = "SDEL-TST-001",
    message: str = "",
    explanation: tuple[str, ...] = (),
    duration: float = 0.001,
    kind: str = "event",
) -> TestResult:
    return TestResult(
        case_id=case_id,
        catalog_id=catalog_id,
        outcome=outcome,
        expected_match=True,
        actual_match=outcome is TestOutcome.PASSED,
        duration_seconds=duration,
        message=message,
        kind=kind,
        explanation=explanation,
    )


def summary(*results: TestResult, evaluator: str = "sdel-matcher") -> TestSummary:
    return TestSummary(results=tuple(results), evaluator=evaluator)


def parse(text: str) -> Any:
    return ElementTree.fromstring(text)


class TestDocumentShape:
    def test_the_xml_declaration_is_first(self) -> None:
        assert render_junit(summary()).startswith('<?xml version="1.0" encoding="UTF-8"?>')

    def test_the_document_is_well_formed(self) -> None:
        assert parse(render_junit(summary(result()))).tag == "testsuites"

    def test_the_suite_is_named(self) -> None:
        root = parse(render_junit(summary()))
        assert root.attrib["name"] == SUITE_NAME

    def test_the_suite_name_is_configurable(self) -> None:
        root = parse(render_junit(summary(), suite_name="custom"))
        assert root.attrib["name"] == "custom"

    def test_a_synthetic_banner_comment_is_present(self) -> None:
        assert "synthetic" in render_junit(summary()).lower()

    def test_the_output_ends_with_a_newline(self) -> None:
        assert render_junit(summary()).endswith("\n")

    def test_an_empty_summary_produces_an_empty_suite_list(self) -> None:
        assert list(parse(render_junit(summary()))) == []

    def test_rendering_is_deterministic(self) -> None:
        report = summary(result())
        assert render_junit(report) == render_junit(report)


class TestTotals:
    def test_the_total_counts_every_result(self) -> None:
        root = parse(render_junit(summary(result(), result(case_id="c2"))))
        assert root.attrib["tests"] == "2"

    def test_failures_are_counted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.FAILED))))
        assert root.attrib["failures"] == "1"

    def test_unsupported_results_count_as_failures(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.UNSUPPORTED))))
        assert root.attrib["failures"] == "1"

    def test_unsupported_results_are_not_counted_as_skips(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.UNSUPPORTED))))
        assert root.attrib["skipped"] == "0"

    def test_errors_are_counted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.ERROR))))
        assert root.attrib["errors"] == "1"

    def test_skips_are_counted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.SKIPPED))))
        assert root.attrib["skipped"] == "1"

    def test_the_total_time_is_summed(self) -> None:
        report = summary(result(duration=0.5), result(case_id="c2", duration=0.25))
        assert parse(render_junit(report)).attrib["time"] == "0.750000"

    def test_header_totals_agree_with_the_case_elements(self) -> None:
        report = summary(
            result(TestOutcome.FAILED),
            result(TestOutcome.UNSUPPORTED, case_id="c2"),
            result(case_id="c3"),
        )
        root = parse(render_junit(report))
        rendered_failures = len(root.findall(".//failure"))
        assert int(root.attrib["failures"]) == rendered_failures


class TestSuiteGrouping:
    def test_one_suite_per_rule(self) -> None:
        report = summary(result(catalog_id="A"), result(catalog_id="B", case_id="c2"))
        assert len(parse(render_junit(report)).findall("testsuite")) == 2

    def test_suites_are_sorted_by_rule(self) -> None:
        report = summary(result(catalog_id="Z"), result(catalog_id="A", case_id="c2"))
        names = [suite.attrib["name"] for suite in parse(render_junit(report))]
        assert names == ["A", "Z"]

    def test_cases_of_one_rule_share_a_suite(self) -> None:
        report = summary(result(case_id="c1"), result(case_id="c2"))
        suites = parse(render_junit(report)).findall("testsuite")
        assert len(suites) == 1
        assert len(suites[0].findall("testcase")) == 2

    def test_suite_totals_are_local(self) -> None:
        report = summary(
            result(TestOutcome.FAILED, catalog_id="A"),
            result(catalog_id="B", case_id="c2"),
        )
        suites = {s.attrib["name"]: s for s in parse(render_junit(report))}
        assert suites["A"].attrib["failures"] == "1"
        assert suites["B"].attrib["failures"] == "0"

    def test_the_evaluator_is_recorded_as_a_property(self) -> None:
        root = parse(render_junit(summary(result(), evaluator="my-evaluator")))
        properties = root.find(".//property[@name='evaluator']")
        assert properties.attrib["value"] == "my-evaluator"

    def test_the_data_source_is_recorded_as_a_property(self) -> None:
        root = parse(render_junit(summary(result())))
        prop = root.find(".//property[@name='data-source']")
        assert "synthetic" in prop.attrib["value"].lower()


class TestCaseRendering:
    def test_the_case_is_named_by_its_id(self) -> None:
        root = parse(render_junit(summary(result(case_id="a-case"))))
        assert root.find(".//testcase").attrib["name"] == "a-case"

    def test_the_classname_is_the_rule(self) -> None:
        root = parse(render_junit(summary(result(catalog_id="SDEL-WIN-001"))))
        assert root.find(".//testcase").attrib["classname"] == "SDEL-WIN-001"

    def test_the_duration_is_recorded(self) -> None:
        root = parse(render_junit(summary(result(duration=0.125))))
        assert root.find(".//testcase").attrib["time"] == "0.125000"

    def test_a_passing_case_has_no_children(self) -> None:
        root = parse(render_junit(summary(result())))
        assert list(root.find(".//testcase")) == []

    def test_a_failure_element_is_emitted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.FAILED, message="nope"))))
        assert root.find(".//failure").attrib["message"] == "nope"

    def test_a_failure_has_a_type(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.FAILED))))
        assert root.find(".//failure").attrib["type"] == "behavioral-expectation"

    def test_a_failure_without_a_message_gets_a_default(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.FAILED))))
        assert root.find(".//failure").attrib["message"] == "expectation not met"

    def test_an_error_element_is_emitted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.ERROR, message="boom"))))
        assert root.find(".//error").attrib["message"] == "boom"

    def test_an_error_has_a_type(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.ERROR))))
        assert root.find(".//error").attrib["type"] == "evaluation-error"

    def test_an_unsupported_result_becomes_a_failure(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.UNSUPPORTED))))
        assert root.find(".//failure") is not None
        assert root.find(".//skipped") is None

    def test_the_unsupported_failure_has_its_own_type(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.UNSUPPORTED))))
        assert root.find(".//failure").attrib["type"] == "unsupported-construct"

    def test_the_unsupported_failure_explains_the_policy(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.UNSUPPORTED))))
        assert "cannot pass by default" in root.find(".//failure").text

    def test_a_skip_element_is_emitted(self) -> None:
        root = parse(render_junit(summary(result(TestOutcome.SKIPPED, message="no fixtures"))))
        assert root.find(".//skipped").attrib["message"] == "no fixtures"

    def test_an_explanation_becomes_failure_detail(self) -> None:
        report = summary(result(TestOutcome.FAILED, explanation=("selection did not match",)))
        root = parse(render_junit(report))
        assert "selection did not match" in root.find(".//failure").text

    def test_an_explanation_on_a_pass_becomes_system_out(self) -> None:
        report = summary(result(explanation=("selection matched",)))
        root = parse(render_junit(report))
        assert "selection matched" in root.find(".//system-out").text


class TestEscaping:
    def test_angle_brackets_in_a_message_are_escaped(self) -> None:
        text = render_junit(summary(result(TestOutcome.FAILED, message="<broken>")))
        assert "<broken>" not in text
        assert parse(text).find(".//failure").attrib["message"] == "<broken>"

    def test_quotes_in_a_case_id_are_escaped(self) -> None:
        text = render_junit(summary(result(case_id='say "hi"')))
        assert parse(text).find(".//testcase").attrib["name"] == 'say "hi"'

    def test_ampersands_in_an_explanation_are_escaped(self) -> None:
        text = render_junit(summary(result(TestOutcome.FAILED, explanation=("a & b",))))
        assert parse(text).find(".//failure").text == "a & b"

    def test_a_document_with_hostile_content_still_parses(self) -> None:
        report = summary(
            result(
                TestOutcome.FAILED,
                case_id="]]><!--",
                message='" onload="alert(1)',
                explanation=("<![CDATA[",),
            )
        )
        assert parse(render_junit(report)).tag == "testsuites"


class TestWriting:
    def test_the_file_is_created(self, tmp_path: Path) -> None:
        assert write_junit(summary(result()), tmp_path / "junit.xml").is_file()

    def test_parent_directories_are_created(self, tmp_path: Path) -> None:
        assert write_junit(summary(), tmp_path / "a" / "b" / "junit.xml").parent.is_dir()

    def test_line_endings_are_lf(self, tmp_path: Path) -> None:
        target = write_junit(summary(result()), tmp_path / "junit.xml")
        assert b"\r\n" not in target.read_bytes()

    def test_the_written_file_parses(self, tmp_path: Path) -> None:
        target = write_junit(summary(result()), tmp_path / "junit.xml")
        assert ElementTree.parse(target).getroot().tag == "testsuites"

    def test_the_suite_name_is_forwarded(self, tmp_path: Path) -> None:
        target = write_junit(summary(), tmp_path / "junit.xml", suite_name="ci")
        assert ElementTree.parse(target).getroot().attrib["name"] == "ci"

    def test_the_written_text_matches_the_rendered_text(self, tmp_path: Path) -> None:
        report = summary(result())
        target = write_junit(report, tmp_path / "junit.xml")
        assert target.read_text(encoding="utf-8") == render_junit(report)


class TestRealRun:
    @pytest.mark.parametrize("outcome", list(TestOutcome))
    def test_every_outcome_renders_a_valid_document(self, outcome: TestOutcome) -> None:
        assert parse(render_junit(summary(result(outcome)))).tag == "testsuites"

    def test_a_real_summary_renders(self, real_summary: TestSummary) -> None:
        assert parse(render_junit(real_summary)).tag == "testsuites"

    def test_a_real_summary_totals_match(self, real_summary: TestSummary) -> None:
        root = parse(render_junit(real_summary))
        assert int(root.attrib["tests"]) == real_summary.total

    def test_a_real_summary_writes(self, real_summary: TestSummary, tmp_path: Path) -> None:
        target = write_junit(real_summary, tmp_path / "real.xml")
        assert ElementTree.parse(target).getroot().tag == "testsuites"
