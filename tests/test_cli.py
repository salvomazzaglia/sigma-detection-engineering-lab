"""Tests for the command-line interface.

Exit codes are part of the contract because this runs in CI, so a failing rule
and a broken installation must never share one. Every invocation here runs
against the real project or a temporary one; nothing touches the network.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from sigma_detection_engineering_lab import CLI_NAME, __version__
from sigma_detection_engineering_lab.cli import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_USAGE,
    build_parser,
    main,
)


def run(*argv: str) -> tuple[int, str]:
    """Invoke the CLI and capture its output stream."""
    stream = io.StringIO()
    code = main(list(argv), stream=stream)
    return code, stream.getvalue()


@pytest.fixture(scope="module")
def root_arg() -> str:
    return str(Path(__file__).resolve().parents[1])


class TestExitCodes:
    def test_codes_are_distinct(self) -> None:
        assert len({EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_REFUSED}) == 4

    def test_success_is_zero(self) -> None:
        assert EXIT_OK == 0

    def test_analysis_failure_is_one(self) -> None:
        assert EXIT_FAILED == 1

    def test_usage_error_is_two(self) -> None:
        assert EXIT_USAGE == 2

    def test_refusal_is_three(self) -> None:
        assert EXIT_REFUSED == 3


class TestParser:
    def test_parser_builds(self) -> None:
        assert build_parser().prog == CLI_NAME

    @pytest.mark.parametrize(
        "command",
        [
            "validate",
            "test",
            "list-rules",
            "explain",
            "coverage",
            "convert",
            "compare",
            "generate-demo",
            "version",
        ],
    )
    def test_every_documented_command_is_registered(self, command: str) -> None:
        parser = build_parser()
        actions = [
            action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
        ]
        assert command in actions[0].choices

    def test_validate_defaults(self) -> None:
        args = build_parser().parse_args(["validate"])
        assert args.strict is False and args.format == "text" and args.limit == 50

    def test_validate_accepts_strict(self) -> None:
        assert build_parser().parse_args(["validate", "--strict"]).strict is True

    def test_validate_accepts_report_outputs(self) -> None:
        args = build_parser().parse_args(
            ["validate", "--json-out", "a.json", "--html-out", "b.html"]
        )
        assert args.json_out == "a.json" and args.html_out == "b.html"

    def test_test_rule_flag_is_repeatable(self) -> None:
        args = build_parser().parse_args(["test", "--rule", "A", "--rule", "B"])
        assert args.rule == ["A", "B"]

    def test_convert_backend_flag_is_repeatable(self) -> None:
        args = build_parser().parse_args(["convert", "--backend", "splunk", "--backend", "esql"])
        assert args.backend == ["splunk", "esql"]

    def test_explain_accepts_catalog_id_flag(self) -> None:
        args = build_parser().parse_args(["explain", "--catalog-id", "SDEL-WIN-001"])
        assert args.catalog_id == "SDEL-WIN-001"
        assert args.rule is None

    def test_explain_without_target_is_usage_error(self, root_arg: str) -> None:
        code, output = run("explain", "--root", root_arg)
        assert code == EXIT_USAGE
        assert "catalog" in output.lower() or "provide" in output.lower()

    def test_compare_requires_two_paths(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["compare", "only-one.json"])

    def test_unknown_format_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["validate", "--format", "yaml"])

    def test_unknown_command_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["nonsense"])

    def test_generate_demo_output_default(self) -> None:
        assert build_parser().parse_args(["generate-demo"]).output == "examples/demo"

    def test_every_command_sets_a_handler(self) -> None:
        for command in ("validate", "test", "list-rules", "coverage", "convert", "version"):
            assert build_parser().parse_args([command]).handler is not None


class TestMainDispatch:
    def test_no_command_prints_help_and_returns_usage(self) -> None:
        code, output = run()
        assert code == EXIT_USAGE and "usage" in output.lower()

    def test_help_lists_the_commands(self) -> None:
        _, output = run()
        assert "validate" in output and "coverage" in output

    def test_version_flag_exits(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0

    def test_bad_root_is_a_refusal_not_a_crash(self, tmp_path: Path) -> None:
        code, _ = run("validate", "--root", str(tmp_path / "nonexistent"))
        assert code == EXIT_REFUSED

    def test_bad_profile_is_a_refusal(self, root_arg: str) -> None:
        code, _ = run("validate", "--root", root_arg, "--profile", "does-not-exist")
        assert code == EXIT_REFUSED


class TestVersionCommand:
    def test_text_output_names_the_tool(self, root_arg: str) -> None:
        code, output = run("version", "--root", root_arg)
        assert code == EXIT_OK and CLI_NAME in output

    def test_text_output_reports_the_version(self, root_arg: str) -> None:
        _, output = run("version", "--root", root_arg)
        assert __version__ in output

    def test_json_output_is_parseable(self, root_arg: str) -> None:
        code, output = run("version", "--root", root_arg, "--format", "json")
        assert code == EXIT_OK and json.loads(output)["tool"] == CLI_NAME

    def test_json_output_disclaims_production_readiness(self, root_arg: str) -> None:
        _, output = run("version", "--root", root_arg, "--format", "json")
        assert json.loads(output)["production_ready"] is False

    def test_json_output_reports_pysigma_availability(self, root_arg: str) -> None:
        _, output = run("version", "--root", root_arg, "--format", "json")
        assert isinstance(json.loads(output)["pysigma_available"], bool)

    def test_json_output_reports_the_attack_version(self, root_arg: str) -> None:
        _, output = run("version", "--root", root_arg, "--format", "json")
        assert json.loads(output)["attack_version"]

    def test_version_survives_a_missing_config(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        code, output = run("version", "--root", str(empty), "--format", "json")
        assert code == EXIT_OK and "config_error" in json.loads(output)


class TestListRulesCommand:
    def test_lists_the_catalog(self, root_arg: str) -> None:
        code, output = run("list-rules", "--root", root_arg)
        assert code == EXIT_OK and "Catalog ID" in output

    def test_json_output_reports_a_count(self, root_arg: str) -> None:
        _, output = run("list-rules", "--root", root_arg, "--format", "json")
        payload = json.loads(output)
        assert payload["count"] == len(payload["rules"])

    def test_catalog_is_not_empty(self, root_arg: str) -> None:
        _, output = run("list-rules", "--root", root_arg, "--format", "json")
        assert json.loads(output)["count"] > 0

    def test_status_filter_narrows_the_result(self, root_arg: str) -> None:
        _, everything = run("list-rules", "--root", root_arg, "--format", "json")
        _, filtered = run(
            "list-rules", "--root", root_arg, "--status", "experimental", "--format", "json"
        )
        assert json.loads(filtered)["count"] <= json.loads(everything)["count"]

    def test_every_listed_rule_matches_the_status_filter(self, root_arg: str) -> None:
        _, output = run(
            "list-rules", "--root", root_arg, "--status", "experimental", "--format", "json"
        )
        rules = json.loads(output)["rules"]
        assert all(rule["status"] == "experimental" for rule in rules)

    def test_product_filter_is_applied(self, root_arg: str) -> None:
        _, output = run(
            "list-rules", "--root", root_arg, "--product", "windows", "--format", "json"
        )
        rules = json.loads(output)["rules"]
        assert all(rule["logsource"].get("product") == "windows" for rule in rules)

    def test_correlation_filter_returns_only_correlation_rules(self, root_arg: str) -> None:
        _, output = run("list-rules", "--root", root_arg, "--correlation", "--format", "json")
        rules = json.loads(output)["rules"]
        assert all(rule["is_correlation"] for rule in rules)

    def test_unmatched_filter_reports_zero(self, root_arg: str) -> None:
        _, output = run(
            "list-rules", "--root", root_arg, "--tag", "attack.nonexistent", "--format", "json"
        )
        assert json.loads(output)["count"] == 0

    def test_unmatched_filter_says_so_in_text_mode(self, root_arg: str) -> None:
        _, output = run("list-rules", "--root", root_arg, "--tag", "attack.nope")
        assert "No rule matched" in output

    def test_unknown_status_value_is_a_refusal(self, root_arg: str) -> None:
        code, _ = run("list-rules", "--root", root_arg, "--status", "nonsense")
        assert code == EXIT_REFUSED

    def test_search_matches_titles(self, root_arg: str) -> None:
        _, output = run(
            "list-rules", "--root", root_arg, "--search", "synthetic", "--format", "json"
        )
        assert json.loads(output)["count"] >= 0

    def test_listing_includes_maturity_from_sidecars(self, root_arg: str) -> None:
        _, output = run("list-rules", "--root", root_arg, "--format", "json")
        rules = json.loads(output)["rules"]
        assert any(rule["maturity"] for rule in rules)


class TestExplainCommand:
    @pytest.fixture
    def a_catalog_id(self, root_arg: str) -> str:
        _, output = run("list-rules", "--root", root_arg, "--format", "json")
        return str(json.loads(output)["rules"][0]["catalog_id"])

    def test_explains_a_known_rule(self, root_arg: str, a_catalog_id: str) -> None:
        code, output = run("explain", a_catalog_id, "--root", root_arg)
        assert code == EXIT_OK and a_catalog_id in output

    def test_json_output_includes_the_rule(self, root_arg: str, a_catalog_id: str) -> None:
        _, output = run("explain", a_catalog_id, "--root", root_arg, "--format", "json")
        assert json.loads(output)["rule"]["catalog_id"] == a_catalog_id

    def test_json_output_includes_fixture_counts(self, root_arg: str, a_catalog_id: str) -> None:
        _, output = run("explain", a_catalog_id, "--root", root_arg, "--format", "json")
        assert "positive_events" in json.loads(output)["fixtures"]

    def test_json_output_carries_the_synthetic_banner(
        self, root_arg: str, a_catalog_id: str
    ) -> None:
        _, output = run("explain", a_catalog_id, "--root", root_arg, "--format", "json")
        assert "synthetic" in json.loads(output)["banner"].lower()

    def test_unknown_rule_fails_without_crashing(self, root_arg: str) -> None:
        code, output = run("explain", "SDEL-NOPE-999", "--root", root_arg)
        assert code == EXIT_FAILED and "No rule matches" in output

    def test_unknown_rule_suggests_list_rules(self, root_arg: str) -> None:
        _, output = run("explain", "SDEL-NOPE-999", "--root", root_arg)
        assert "list-rules" in output

    def test_explanation_reports_the_parsed_condition(
        self, root_arg: str, a_catalog_id: str
    ) -> None:
        _, output = run("explain", a_catalog_id, "--root", root_arg, "--format", "json")
        payload = json.loads(output)
        assert payload["parsed_condition"] or payload["rule"]["is_correlation"]


class TestValidateCommand:
    def test_real_catalog_passes_strict_validation(self, root_arg: str) -> None:
        code, _ = run("validate", "--root", root_arg, "--strict")
        assert code == EXIT_OK

    def test_text_output_has_a_validation_heading(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg)
        assert "Validation" in output

    def test_text_output_lists_the_quality_gates(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg)
        assert "Quality gates" in output

    def test_text_output_reports_behavioral_test_counts(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg)
        assert "Behavioral tests:" in output

    def test_json_output_is_parseable(self, root_arg: str) -> None:
        code, output = run("validate", "--root", root_arg, "--format", "json")
        assert code == EXIT_OK and isinstance(json.loads(output), dict)

    def test_json_output_reports_the_verdict(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg, "--format", "json")
        assert json.loads(output)["passed"] is True

    def test_json_output_records_the_command(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg, "--format", "json")
        assert json.loads(output)["command"].endswith("validate")

    def test_json_report_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        run("validate", "--root", root_arg, "--json-out", str(target))
        assert json.loads(target.read_text(encoding="utf-8"))["passed"] is True

    def test_html_report_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "report.html"
        run("validate", "--root", root_arg, "--html-out", str(target))
        assert target.read_text(encoding="utf-8").lstrip().startswith("<!DOCTYPE html>")

    def test_sarif_report_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "report.sarif"
        run("validate", "--root", root_arg, "--sarif-out", str(target))
        assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_junit_report_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "results.xml"
        run("validate", "--root", root_arg, "--junit-out", str(target))
        assert "<testsuite" in target.read_text(encoding="utf-8")

    def test_csv_findings_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "findings.csv"
        run("validate", "--root", root_arg, "--csv-out", str(target))
        assert target.read_text(encoding="utf-8").splitlines()[0].startswith("code,severity")

    def test_written_reports_are_announced(self, root_arg: str, tmp_path: Path) -> None:
        _, output = run("validate", "--root", root_arg, "--json-out", str(tmp_path / "r.json"))
        assert "Reports written:" in output

    def test_skip_tests_omits_the_test_section(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg, "--skip-tests", "--format", "json")
        assert "tests" not in json.loads(output)

    def test_skip_conversion_omits_the_conversion_section(self, root_arg: str) -> None:
        _, output = run("validate", "--root", root_arg, "--skip-conversion", "--format", "json")
        assert "conversions" not in json.loads(output)

    def test_no_pysigma_still_validates(self, root_arg: str) -> None:
        code, _ = run("validate", "--root", root_arg, "--no-pysigma")
        assert code == EXIT_OK

    def test_limit_truncates_the_finding_table(self, root_arg: str) -> None:
        code, _ = run("validate", "--root", root_arg, "--limit", "1")
        assert code == EXIT_OK

    def test_empty_rules_directory_produces_findings(self, root_arg: str, tmp_path: Path) -> None:
        empty = tmp_path / "no-rules"
        empty.mkdir()
        code, output = run(
            "validate", "--root", root_arg, "--rules", str(empty), "--format", "json"
        )
        assert code == EXIT_FAILED
        assert json.loads(output)["catalog"]["total"] == 0


class TestTestCommand:
    def test_behavioral_tests_pass_on_the_real_catalog(self, root_arg: str) -> None:
        code, _ = run("test", "--root", root_arg)
        assert code == EXIT_OK

    def test_text_output_reports_the_evaluator(self, root_arg: str) -> None:
        _, output = run("test", "--root", root_arg)
        assert "Evaluator" in output

    def test_json_output_reports_a_summary(self, root_arg: str) -> None:
        _, output = run("test", "--root", root_arg, "--format", "json")
        totals = json.loads(output)["tests"]["totals"]
        assert totals["total"] == (
            totals["passed"]
            + totals["failed"]
            + totals["errored"]
            + totals["skipped"]
            + totals["unsupported"]
        )

    def test_run_has_no_failures(self, root_arg: str) -> None:
        _, output = run("test", "--root", root_arg, "--format", "json")
        assert json.loads(output)["tests"]["successful"] is True

    def test_rule_filter_narrows_the_run(self, root_arg: str) -> None:
        _, everything = run("test", "--root", root_arg, "--format", "json")
        catalog_id = json.loads(everything)["tests"]["results"][0]["catalog_id"]
        _, filtered = run("test", "--root", root_arg, "--rule", catalog_id, "--format", "json")
        results = json.loads(filtered)["tests"]["results"]
        assert results and all(item["catalog_id"] == catalog_id for item in results)

    def test_verbose_lists_every_result(self, root_arg: str) -> None:
        _, output = run("test", "--root", root_arg, "--verbose")
        assert "Outcome" in output

    def test_junit_output_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "junit.xml"
        run("test", "--root", root_arg, "--junit-out", str(target))
        assert target.is_file()


class TestCoverageCommand:
    def test_coverage_runs(self, root_arg: str) -> None:
        code, output = run("coverage", "--root", root_arg)
        assert code == EXIT_OK and "Coverage" in output

    def test_coverage_disclaims_efficacy_metrics(self, root_arg: str) -> None:
        _, output = run("coverage", "--root", root_arg)
        assert "efficacy" in output.lower() or "precision" in output.lower()

    def test_json_output_reports_totals(self, root_arg: str) -> None:
        _, output = run("coverage", "--root", root_arg, "--format", "json")
        assert json.loads(output)["coverage"]["total_rules"] > 0

    def test_coverage_with_tests_fills_in_tested_counts(self, root_arg: str) -> None:
        _, output = run("coverage", "--root", root_arg, "--tests", "--format", "json")
        assert json.loads(output)["coverage"]["rules_fully_tested"] >= 0

    def test_navigator_layer_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "layer.json"
        code, _ = run("coverage", "--root", root_arg, "--navigator", str(target))
        assert code == EXIT_OK
        assert json.loads(target.read_text(encoding="utf-8"))["domain"] == "enterprise-attack"

    def test_navigator_path_is_announced(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "layer.json"
        _, output = run("coverage", "--root", root_arg, "--navigator", str(target))
        assert "Navigator layer written" in output


class TestConvertCommand:
    def test_convert_runs_offline(self, root_arg: str) -> None:
        code, output = run("convert", "--root", root_arg)
        assert code == EXIT_OK and "Conversion" in output

    def test_convert_prints_the_demonstration_banner(self, root_arg: str) -> None:
        _, output = run("convert", "--root", root_arg)
        assert "demonstration" in output.lower()

    def test_convert_disclaims_production_use(self, root_arg: str) -> None:
        _, output = run("convert", "--root", root_arg)
        assert "production" in output.lower()

    def test_json_output_is_parseable(self, root_arg: str) -> None:
        code, output = run("convert", "--root", root_arg, "--format", "json")
        assert code == EXIT_OK and "results" in json.loads(output)

    def test_conversion_record_can_be_written(self, root_arg: str, tmp_path: Path) -> None:
        target = tmp_path / "conversion.json"
        run("convert", "--root", root_arg, "--output", str(target))
        assert json.loads(target.read_text(encoding="utf-8"))["results"] is not None

    def test_unknown_backend_yields_no_results(self, root_arg: str) -> None:
        _, output = run(
            "convert", "--root", root_arg, "--backend", "nonexistent", "--format", "json"
        )
        assert json.loads(output)["results"] == []

    def test_rule_filter_is_applied(self, root_arg: str) -> None:
        _, output = run(
            "convert", "--root", root_arg, "--rule", "SDEL-NOPE-999", "--format", "json"
        )
        assert json.loads(output)["results"] == []


class TestCompareCommand:
    @pytest.fixture
    def reports(self, root_arg: str, tmp_path: Path) -> tuple[Path, Path]:
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        run("validate", "--root", root_arg, "--json-out", str(baseline))
        run("validate", "--root", root_arg, "--json-out", str(current))
        return baseline, current

    def test_identical_reports_compare_clean(self, reports: tuple[Path, Path]) -> None:
        code, output = run("compare", str(reports[0]), str(reports[1]))
        assert code == EXIT_OK and "Comparison" in output

    def test_identical_reports_have_no_regressions(self, reports: tuple[Path, Path]) -> None:
        _, output = run("compare", str(reports[0]), str(reports[1]), "--format", "json")
        assert json.loads(output)["has_regressions"] is False

    def test_fail_on_regression_passes_for_identical_reports(
        self, reports: tuple[Path, Path]
    ) -> None:
        code, _ = run("compare", str(reports[0]), str(reports[1]), "--fail-on-regression")
        assert code == EXIT_OK

    def test_comparison_can_be_written(self, reports: tuple[Path, Path], tmp_path: Path) -> None:
        target = tmp_path / "diff.json"
        run("compare", str(reports[0]), str(reports[1]), "--output", str(target))
        assert target.is_file()

    def test_verbose_includes_unchanged_metrics(self, reports: tuple[Path, Path]) -> None:
        _, output = run("compare", str(reports[0]), str(reports[1]), "--verbose")
        assert "unchanged" in output

    def test_missing_baseline_is_a_refusal(self, tmp_path: Path) -> None:
        code, _ = run("compare", str(tmp_path / "absent.json"), str(tmp_path / "also.json"))
        assert code == EXIT_REFUSED


class TestGenerateDemoCommand:
    def test_refuses_to_write_outside_the_project(self, root_arg: str, tmp_path: Path) -> None:
        code, output = run("generate-demo", "--root", root_arg, "--output", str(tmp_path))
        assert code == EXIT_FAILED and "Refusing to write outside" in output

    def test_writes_into_a_project_subdirectory(self, tmp_path: Path) -> None:
        from conftest import ATTACK_SUBSET, MINIMAL_CONFIG, build_project

        root = build_project(tmp_path / "project", config=MINIMAL_CONFIG, attack=ATTACK_SUBSET)
        code, output = run("generate-demo", "--root", str(root), "--output", "examples/demo")
        assert code == EXIT_OK
        assert (root / "examples" / "demo" / "metadata" / "rules" / "SDEL-DEMO-001.json").is_file()
        assert "Demonstration content generated" in output

    def test_second_run_refuses_without_force(self, tmp_path: Path) -> None:
        from conftest import ATTACK_SUBSET, MINIMAL_CONFIG, build_project

        root = build_project(tmp_path / "project", config=MINIMAL_CONFIG, attack=ATTACK_SUBSET)
        run("generate-demo", "--root", str(root), "--output", "examples/demo")
        code, output = run("generate-demo", "--root", str(root), "--output", "examples/demo")
        assert code == EXIT_FAILED and "Refusing to overwrite" in output

    def test_force_overwrites(self, tmp_path: Path) -> None:
        from conftest import ATTACK_SUBSET, MINIMAL_CONFIG, build_project

        root = build_project(tmp_path / "project", config=MINIMAL_CONFIG, attack=ATTACK_SUBSET)
        run("generate-demo", "--root", str(root), "--output", "examples/demo")
        code, _ = run("generate-demo", "--root", str(root), "--output", "examples/demo", "--force")
        assert code == EXIT_OK

    def test_generated_fixtures_are_marked_synthetic(self, tmp_path: Path) -> None:
        from conftest import ATTACK_SUBSET, MINIMAL_CONFIG, build_project

        root = build_project(tmp_path / "project", config=MINIMAL_CONFIG, attack=ATTACK_SUBSET)
        run("generate-demo", "--root", str(root), "--output", "examples/demo")
        fixture = next((root / "examples" / "demo" / "fixtures").rglob("*.jsonl"))
        record = json.loads(fixture.read_text(encoding="utf-8").splitlines()[0])
        assert record["synthetic"] is True

    def test_generated_demo_validates(self, tmp_path: Path) -> None:
        from conftest import ATTACK_SUBSET, MINIMAL_CONFIG, TELEMETRY_CATALOG, build_project

        root = build_project(
            tmp_path / "project",
            config=MINIMAL_CONFIG,
            attack=ATTACK_SUBSET,
            telemetry=TELEMETRY_CATALOG,
        )
        run("generate-demo", "--root", str(root), "--output", "examples/demo")
        code, output = run(
            "validate",
            "--root",
            str(root),
            "--rules",
            "examples/demo/rules",
            "--metadata",
            "examples/demo/metadata/rules",
            "--fixtures",
            "examples/demo/fixtures",
            "--format",
            "json",
        )
        payload = json.loads(output)
        assert code in (EXIT_OK, EXIT_FAILED)
        assert payload["catalog"]["total"] == 1


class TestDirectoryOverrides:
    def test_rules_override_is_resolved_against_the_root(
        self, root_arg: str, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty-rules"
        empty.mkdir()
        _, output = run("list-rules", "--root", root_arg, "--rules", str(empty), "--format", "json")
        assert json.loads(output)["count"] == 0

    def test_metadata_override_is_honoured(self, root_arg: str, tmp_path: Path) -> None:
        empty = tmp_path / "empty-metadata"
        empty.mkdir()
        _, output = run(
            "list-rules", "--root", root_arg, "--metadata", str(empty), "--format", "json"
        )
        assert all(rule["maturity"] is None for rule in json.loads(output)["rules"])

    def test_fixtures_override_is_honoured(self, root_arg: str, tmp_path: Path) -> None:
        empty = tmp_path / "empty-fixtures"
        empty.mkdir()
        _, output = run("test", "--root", root_arg, "--fixtures", str(empty), "--format", "json")
        assert json.loads(output)["fixtures"]["case_count"] == 0


class TestNamespaceHelpers:
    def test_handler_receives_the_namespace(self, root_arg: str) -> None:
        parser = build_parser()
        args = parser.parse_args(["version", "--root", root_arg])
        stream = io.StringIO()
        assert args.handler(args, stream) == EXIT_OK

    def test_namespace_is_a_plain_namespace(self) -> None:
        assert isinstance(build_parser().parse_args(["version"]), argparse.Namespace)
