"""SARIF output: a quality transport that never impersonates a security scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import make_finding

from sigma_detection_engineering_lab.models import FindingCategory
from sigma_detection_engineering_lab.sarif_report import (
    INFORMATION_URI,
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    build_sarif,
    render_sarif,
    write_sarif,
)
from sigma_detection_engineering_lab.severities import Severity

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def run(document: dict) -> dict:
    return document["runs"][0]


def driver(document: dict) -> dict:
    return run(document)["tool"]["driver"]


class TestDocumentEnvelope:
    def test_the_schema_is_declared(self) -> None:
        assert build_sarif([])["$schema"] == SARIF_SCHEMA

    def test_the_version_is_declared(self) -> None:
        assert build_sarif([])["version"] == SARIF_VERSION

    def test_the_version_is_two_one_zero(self) -> None:
        assert SARIF_VERSION == "2.1.0"

    def test_there_is_exactly_one_run(self) -> None:
        assert len(build_sarif([])["runs"]) == 1

    def test_the_tool_is_named(self) -> None:
        assert driver(build_sarif([]))["name"] == TOOL_NAME

    def test_the_tool_declares_a_version(self) -> None:
        assert driver(build_sarif([]))["version"]

    def test_the_tool_declares_a_semantic_version(self) -> None:
        assert driver(build_sarif([]))["semanticVersion"]

    def test_the_information_uri_is_declared(self) -> None:
        assert driver(build_sarif([]))["informationUri"] == INFORMATION_URI

    def test_an_empty_run_has_no_results(self) -> None:
        assert run(build_sarif([]))["results"] == []

    def test_an_empty_run_has_no_rules(self) -> None:
        assert driver(build_sarif([]))["rules"] == []


class TestQualityNotVulnerability:
    def test_the_run_denies_being_a_vulnerability_report(self) -> None:
        assert run(build_sarif([]))["properties"]["isVulnerabilityFinding"] is False

    def test_the_driver_denies_being_a_vulnerability_report(self) -> None:
        assert driver(build_sarif([]))["properties"]["isVulnerabilityFinding"] is False

    def test_the_category_is_detection_engineering_quality(self) -> None:
        assert run(build_sarif([]))["properties"]["category"] == "detection-engineering-quality"

    def test_the_run_denies_production_readiness(self) -> None:
        assert run(build_sarif([]))["properties"]["productionReady"] is False

    def test_the_run_carries_a_disclaimer(self) -> None:
        assert run(build_sarif([]))["properties"]["disclaimer"]

    def test_no_rule_carries_a_security_severity(self) -> None:
        document = build_sarif([make_finding(severity=Severity.CRITICAL)])
        assert "security-severity" not in json.dumps(document)

    def test_every_rule_is_tagged_as_quality(self) -> None:
        document = build_sarif([make_finding()])
        assert "quality" in driver(document)["rules"][0]["properties"]["tags"]

    def test_every_rule_is_tagged_as_detection_engineering(self) -> None:
        document = build_sarif([make_finding()])
        assert "detection-engineering" in driver(document)["rules"][0]["properties"]["tags"]

    def test_every_result_denies_being_a_vulnerability(self) -> None:
        document = build_sarif([make_finding()])
        assert run(document)["results"][0]["properties"]["isVulnerabilityFinding"] is False

    def test_the_note_explains_the_distinction(self) -> None:
        assert "not" in run(build_sarif([]))["properties"]["note"].lower()


class TestRuleDescriptors:
    def test_one_descriptor_per_code(self) -> None:
        findings = [make_finding(code="A"), make_finding(code="A"), make_finding(code="B")]
        assert len(driver(build_sarif(findings))["rules"]) == 2

    def test_descriptors_are_sorted_by_code(self) -> None:
        findings = [make_finding(code="Z"), make_finding(code="A")]
        ids = [rule["id"] for rule in driver(build_sarif(findings))["rules"]]
        assert ids == ["A", "Z"]

    def test_the_descriptor_id_is_the_code(self) -> None:
        document = build_sarif([make_finding(code="SDEL-MET-002")])
        assert driver(document)["rules"][0]["id"] == "SDEL-MET-002"

    def test_the_descriptor_name_is_pascal_case(self) -> None:
        finding = make_finding(code="SDEL-MET-002", category=FindingCategory.METADATA)
        document = build_sarif([finding])
        assert driver(document)["rules"][0]["name"] == "MetadataMET002"

    def test_the_short_description_uses_the_message(self) -> None:
        document = build_sarif([make_finding(message="a problem; with detail")])
        assert driver(document)["rules"][0]["shortDescription"]["text"] == "a problem"

    def test_the_short_description_is_length_bounded(self) -> None:
        document = build_sarif([make_finding(message="x" * 400)])
        assert len(driver(document)["rules"][0]["shortDescription"]["text"]) <= 200

    def test_the_full_description_names_the_category(self) -> None:
        document = build_sarif([make_finding(category=FindingCategory.METADATA)])
        assert "metadata" in driver(document)["rules"][0]["fullDescription"]["text"]

    def test_the_default_level_follows_the_severity(self) -> None:
        document = build_sarif([make_finding(severity=Severity.CRITICAL)])
        assert driver(document)["rules"][0]["defaultConfiguration"]["level"] == "error"

    def test_remediation_becomes_help_text(self) -> None:
        document = build_sarif([make_finding(remediation="do the thing")])
        assert driver(document)["rules"][0]["help"]["text"] == "do the thing"

    def test_help_is_omitted_without_remediation(self) -> None:
        document = build_sarif([make_finding(remediation=None)])
        assert "help" not in driver(document)["rules"][0]

    def test_the_first_available_remediation_is_used(self) -> None:
        findings = [
            make_finding(code="A", remediation=None),
            make_finding(code="A", remediation="fix it"),
        ]
        assert driver(build_sarif(findings))["rules"][0]["help"]["text"] == "fix it"

    def test_the_gate_is_recorded(self) -> None:
        document = build_sarif([make_finding(gate="no_secrets")])
        assert driver(document)["rules"][0]["properties"]["gate"] == "no_secrets"


class TestResults:
    def test_one_result_per_finding(self) -> None:
        assert len(run(build_sarif([make_finding(), make_finding()]))["results"]) == 2

    def test_the_result_references_its_rule(self) -> None:
        document = build_sarif([make_finding(code="SDEL-X-001")])
        assert run(document)["results"][0]["ruleId"] == "SDEL-X-001"

    def test_the_kind_is_fail(self) -> None:
        assert run(build_sarif([make_finding()]))["results"][0]["kind"] == "fail"

    def test_the_message_is_carried(self) -> None:
        document = build_sarif([make_finding(message="something happened")])
        assert run(document)["results"][0]["message"]["text"] == "something happened"

    @pytest.mark.parametrize(
        ("severity", "level"),
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFORMATIONAL, "note"),
        ],
    )
    def test_severities_map_to_sarif_levels(self, severity: Severity, level: str) -> None:
        document = build_sarif([make_finding(severity=severity)])
        assert run(document)["results"][0]["level"] == level

    def test_a_path_becomes_a_physical_location(self) -> None:
        document = build_sarif([make_finding(path="rules/a.yml")])
        location = run(document)["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "rules/a.yml"

    def test_the_uri_base_is_declared(self) -> None:
        document = build_sarif([make_finding(path="rules/a.yml")])
        location = run(document)["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_a_line_becomes_a_region(self) -> None:
        document = build_sarif([make_finding(path="rules/a.yml", line=12)])
        location = run(document)["results"][0]["locations"][0]
        assert location["physicalLocation"]["region"]["startLine"] == 12

    def test_a_missing_line_omits_the_region(self) -> None:
        document = build_sarif([make_finding(path="rules/a.yml", line=None)])
        location = run(document)["results"][0]["locations"][0]
        assert "region" not in location["physicalLocation"]

    def test_a_zero_line_is_ignored(self) -> None:
        document = build_sarif([make_finding(path="rules/a.yml", line=0)])
        location = run(document)["results"][0]["locations"][0]
        assert "region" not in location["physicalLocation"]

    def test_a_pathless_finding_still_has_a_logical_location(self) -> None:
        document = build_sarif([make_finding(path=None, subject="SDEL-X-001")])
        location = run(document)["results"][0]["locations"][0]
        assert location["logicalLocations"][0]["name"] == "SDEL-X-001"

    def test_a_pathless_finding_has_no_physical_location(self) -> None:
        document = build_sarif([make_finding(path=None)])
        assert "physicalLocation" not in run(document)["results"][0]["locations"][0]

    def test_the_subject_is_recorded_in_properties(self) -> None:
        document = build_sarif([make_finding(subject="SDEL-X-002")])
        assert run(document)["results"][0]["properties"]["subject"] == "SDEL-X-002"


class TestInvocation:
    def test_an_empty_run_is_successful(self) -> None:
        assert run(build_sarif([]))["invocations"][0]["executionSuccessful"] is True

    def test_a_low_finding_leaves_the_run_successful(self) -> None:
        document = build_sarif([make_finding(severity=Severity.LOW)])
        assert run(document)["invocations"][0]["executionSuccessful"] is True

    def test_a_critical_finding_makes_the_run_unsuccessful(self) -> None:
        document = build_sarif([make_finding(severity=Severity.CRITICAL)])
        assert run(document)["invocations"][0]["executionSuccessful"] is False

    def test_success_can_be_declared_explicitly(self) -> None:
        document = build_sarif([make_finding(severity=Severity.CRITICAL)], successful=True)
        assert run(document)["invocations"][0]["executionSuccessful"] is True

    def test_the_command_line_is_recorded_when_given(self) -> None:
        document = build_sarif([], invocation_command="sigma-detection-lab validate")
        assert run(document)["invocations"][0]["commandLine"].endswith("validate")

    def test_the_command_line_is_omitted_when_absent(self) -> None:
        assert "commandLine" not in run(build_sarif([]))["invocations"][0]


class TestRedaction:
    def test_findings_are_redacted_by_default(self) -> None:
        document = build_sarif([make_finding(message=f"key={AWS_KEY}")])
        assert AWS_KEY not in json.dumps(document)

    def test_redaction_can_be_disabled_deliberately(self) -> None:
        document = build_sarif([make_finding(message=f"key={AWS_KEY}")], redact=False)
        assert AWS_KEY in json.dumps(document)

    def test_remediation_text_is_redacted(self) -> None:
        document = build_sarif([make_finding(remediation=f"remove key={AWS_KEY}")])
        assert AWS_KEY not in json.dumps(document)


class TestRenderingAndWriting:
    def test_the_output_parses_as_json(self) -> None:
        assert json.loads(render_sarif([]))["version"] == SARIF_VERSION

    def test_keys_are_sorted(self) -> None:
        text = render_sarif([])
        assert text.index('"$schema"') < text.index('"runs"')

    def test_the_output_ends_with_a_newline(self) -> None:
        assert render_sarif([]).endswith("\n")

    def test_rendering_is_deterministic(self) -> None:
        findings = [make_finding()]
        assert render_sarif(findings) == render_sarif(findings)

    def test_the_indent_is_configurable(self) -> None:
        assert "\n    " in render_sarif([], indent=4)

    def test_the_file_is_created(self, tmp_path: Path) -> None:
        assert write_sarif([], tmp_path / "out.sarif").is_file()

    def test_parent_directories_are_created(self, tmp_path: Path) -> None:
        assert write_sarif([], tmp_path / "a" / "b" / "out.sarif").parent.is_dir()

    def test_line_endings_are_lf(self, tmp_path: Path) -> None:
        target = write_sarif([make_finding()], tmp_path / "out.sarif")
        assert b"\r\n" not in target.read_bytes()

    def test_the_written_file_parses(self, tmp_path: Path) -> None:
        target = write_sarif([make_finding()], tmp_path / "out.sarif")
        assert json.loads(target.read_text(encoding="utf-8"))["version"] == SARIF_VERSION

    def test_write_options_are_forwarded(self, tmp_path: Path) -> None:
        target = write_sarif(
            [make_finding()], tmp_path / "out.sarif", invocation_command="validate"
        )
        document = json.loads(target.read_text(encoding="utf-8"))
        assert run(document)["invocations"][0]["commandLine"] == "validate"


class TestManyFindings:
    def test_a_mixed_set_produces_matching_counts(self) -> None:
        findings = [
            make_finding(code=f"SDEL-X-{index:03d}", severity=Severity.MEDIUM)
            for index in range(10)
        ]
        document = build_sarif(findings)
        assert len(run(document)["results"]) == 10
        assert len(driver(document)["rules"]) == 10

    def test_every_result_references_a_declared_rule(self) -> None:
        findings = [make_finding(code="A"), make_finding(code="B")]
        document = build_sarif(findings)
        declared = {rule["id"] for rule in driver(document)["rules"]}
        assert all(result["ruleId"] in declared for result in run(document)["results"])
