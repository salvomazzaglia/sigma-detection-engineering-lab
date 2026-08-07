"""Comparing two saved reports, where direction is judged per metric."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from conftest import write_json
from sigma_detection_engineering_lab.comparison import (
    HIGHER_IS_BETTER,
    LOWER_IS_BETTER,
    TRACKED_COVERAGE_KEYS,
    ComparisonReport,
    Direction,
    MetricChange,
    SetChange,
    classify,
    compare_counts,
    compare_files,
    compare_gates,
    compare_lists,
    compare_metrics,
    compare_reports,
    load_report,
)
from sigma_detection_engineering_lab.errors import ReportError


def coverage(**values: Any) -> dict[str, Any]:
    base = {
        "total_rules": 10,
        "rules_with_sidecar": 10,
        "rules_with_attack_mapping": 10,
        "rules_with_fixtures": 10,
        "rules_fully_tested": 10,
        "technique_counts": {"T1059": 1},
        "tactic_counts": {"ta0002": 1},
        "logsource_counts": {"windows/process_creation": 1},
        "untested_rules": [],
        "unmapped_rules": [],
    }
    base.update(values)
    return {"coverage": base}


def gate_document(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"quality": {"gates": list(entries)}}


class TestDirection:
    def test_the_enum_renders_as_its_value(self) -> None:
        assert str(Direction.IMPROVED) == "improved"

    def test_an_equal_value_is_unchanged(self) -> None:
        assert classify("total_rules", 5, 5) is Direction.UNCHANGED

    def test_more_is_better_for_a_positive_metric(self) -> None:
        assert classify("total_rules", 5, 6) is Direction.IMPROVED

    def test_fewer_is_worse_for_a_positive_metric(self) -> None:
        assert classify("total_rules", 6, 5) is Direction.REGRESSED

    def test_fewer_is_better_for_a_negative_metric(self) -> None:
        assert classify("failed", 3, 1) is Direction.IMPROVED

    def test_more_is_worse_for_a_negative_metric(self) -> None:
        assert classify("failed", 1, 3) is Direction.REGRESSED

    def test_an_unclassified_metric_is_neutral(self) -> None:
        assert classify("mystery", 1, 2) is Direction.NEUTRAL

    @pytest.mark.parametrize("key", sorted(HIGHER_IS_BETTER))
    def test_every_positive_metric_improves_when_it_grows(self, key: str) -> None:
        assert classify(key, 0, 1) is Direction.IMPROVED

    @pytest.mark.parametrize("key", sorted(LOWER_IS_BETTER))
    def test_every_negative_metric_improves_when_it_shrinks(self, key: str) -> None:
        assert classify(key, 1, 0) is Direction.IMPROVED

    def test_the_two_direction_sets_are_disjoint(self) -> None:
        assert HIGHER_IS_BETTER.isdisjoint(LOWER_IS_BETTER)


class TestMetricChange:
    def test_the_delta_is_the_difference(self) -> None:
        assert MetricChange("k", 1.0, 4.0, Direction.IMPROVED).delta == 3.0

    def test_a_negative_delta_is_reported(self) -> None:
        assert MetricChange("k", 4.0, 1.0, Direction.REGRESSED).delta == -3.0

    def test_the_delta_is_rounded(self) -> None:
        assert MetricChange("k", 0.1, 0.3, Direction.IMPROVED).delta == 0.2

    def test_to_dict_carries_the_direction_as_text(self) -> None:
        payload = MetricChange("k", 1.0, 2.0, Direction.IMPROVED).to_dict()
        assert payload["direction"] == "improved"

    def test_to_dict_carries_the_delta(self) -> None:
        assert MetricChange("k", 1.0, 2.0, Direction.IMPROVED).to_dict()["delta"] == 1.0

    def test_a_change_is_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            MetricChange("k", 1.0, 2.0, Direction.IMPROVED).key = "x"  # type: ignore[misc]


class TestSetChange:
    def test_an_empty_change_is_not_changed(self) -> None:
        assert SetChange("k").changed is False

    def test_an_addition_counts_as_changed(self) -> None:
        assert SetChange("k", added=("a",)).changed is True

    def test_a_removal_counts_as_changed(self) -> None:
        assert SetChange("k", removed=("a",)).changed is True

    def test_to_dict_reports_counts(self) -> None:
        payload = SetChange("k", added=("a", "b"), removed=("c",)).to_dict()
        assert (payload["added_count"], payload["removed_count"]) == (2, 1)


class TestCompareMetrics:
    def test_a_present_key_is_compared(self) -> None:
        changes = compare_metrics({"a": 1}, {"a": 2}, ("a",))
        assert changes[0].delta == 1.0

    def test_a_key_absent_from_both_is_skipped(self) -> None:
        assert compare_metrics({}, {}, ("a",)) == ()

    def test_a_key_absent_from_the_baseline_reads_as_zero(self) -> None:
        assert compare_metrics({}, {"a": 3}, ("a",))[0].baseline == 0.0

    def test_a_key_absent_from_the_current_reads_as_zero(self) -> None:
        assert compare_metrics({"a": 3}, {}, ("a",))[0].current == 0.0

    def test_a_boolean_is_read_as_one_or_zero(self) -> None:
        assert compare_metrics({"passed": False}, {"passed": True}, ("passed",))[0].delta == 1.0

    def test_a_non_numeric_value_is_treated_as_absent(self) -> None:
        assert compare_metrics({"a": "x"}, {"a": "y"}, ("a",)) == ()

    def test_the_key_order_is_preserved(self) -> None:
        changes = compare_metrics({"b": 1, "a": 1}, {"b": 2, "a": 2}, ("b", "a"))
        assert [change.key for change in changes] == ["b", "a"]

    def test_a_float_metric_is_compared(self) -> None:
        change = compare_metrics({"tested_ratio": 0.5}, {"tested_ratio": 0.75}, ("tested_ratio",))
        assert change[0].direction is Direction.IMPROVED


class TestCompareCounts:
    def test_an_added_key_is_reported(self) -> None:
        change = compare_counts({"c": {"a": 1}}, {"c": {"a": 1, "b": 1}}, "c")
        assert change.added == ("b",)

    def test_a_removed_key_is_reported(self) -> None:
        change = compare_counts({"c": {"a": 1, "b": 1}}, {"c": {"a": 1}}, "c")
        assert change.removed == ("b",)

    def test_a_count_change_alone_is_not_a_set_change(self) -> None:
        assert compare_counts({"c": {"a": 1}}, {"c": {"a": 5}}, "c").changed is False

    def test_a_missing_section_reads_as_empty(self) -> None:
        assert compare_counts({}, {"c": {"a": 1}}, "c").added == ("a",)

    def test_a_non_mapping_section_reads_as_empty(self) -> None:
        assert compare_counts({"c": ["a"]}, {"c": {"a": 1}}, "c").added == ("a",)

    def test_additions_are_sorted(self) -> None:
        change = compare_counts({"c": {}}, {"c": {"z": 1, "a": 1}}, "c")
        assert change.added == ("a", "z")


class TestCompareLists:
    def test_an_added_entry_is_reported(self) -> None:
        assert compare_lists({"u": []}, {"u": ["a"]}, "u").added == ("a",)

    def test_a_removed_entry_is_reported(self) -> None:
        assert compare_lists({"u": ["a"]}, {"u": []}, "u").removed == ("a",)

    def test_an_unchanged_list_reports_nothing(self) -> None:
        assert compare_lists({"u": ["a"]}, {"u": ["a"]}, "u").changed is False

    def test_ordering_differences_are_not_changes(self) -> None:
        assert compare_lists({"u": ["a", "b"]}, {"u": ["b", "a"]}, "u").changed is False

    def test_a_string_value_reads_as_empty(self) -> None:
        assert compare_lists({"u": "ab"}, {"u": ["a"]}, "u").added == ("a",)

    def test_a_missing_key_reads_as_empty(self) -> None:
        assert compare_lists({}, {"u": ["a"]}, "u").added == ("a",)


class TestCompareGates:
    def test_a_newly_failing_gate_is_reported(self) -> None:
        before = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        after = {"gates": [{"gate": "g", "passed": False, "enabled": True}]}
        assert compare_gates(before, after) == (("g", "passed", "failed"),)

    def test_a_newly_passing_gate_is_reported(self) -> None:
        before = {"gates": [{"gate": "g", "passed": False, "enabled": True}]}
        after = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        assert compare_gates(before, after) == (("g", "failed", "passed"),)

    def test_an_unchanged_gate_is_not_reported(self) -> None:
        document = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        assert compare_gates(document, document) == ()

    def test_a_disabled_gate_is_labelled(self) -> None:
        before = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        after = {"gates": [{"gate": "g", "passed": True, "enabled": False}]}
        assert compare_gates(before, after) == (("g", "passed", "disabled"),)

    def test_a_new_gate_is_reported_as_previously_absent(self) -> None:
        after = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        assert compare_gates({}, after) == (("g", "absent", "passed"),)

    def test_a_removed_gate_is_reported_as_now_absent(self) -> None:
        before = {"gates": [{"gate": "g", "passed": True, "enabled": True}]}
        assert compare_gates(before, {}) == (("g", "passed", "absent"),)

    def test_gates_are_reported_in_sorted_order(self) -> None:
        after = {
            "gates": [
                {"gate": "z", "passed": False, "enabled": True},
                {"gate": "a", "passed": False, "enabled": True},
            ]
        }
        assert [name for name, _, _ in compare_gates({}, after)] == ["a", "z"]

    def test_a_malformed_gate_entry_is_ignored(self) -> None:
        assert compare_gates({}, {"gates": ["not a mapping", {"no_name": 1}]}) == ()

    def test_a_non_list_gates_value_is_ignored(self) -> None:
        assert compare_gates({}, {"gates": "g"}) == ()


class TestCompareReports:
    def test_an_identical_pair_has_no_regressions(self) -> None:
        document = coverage()
        assert compare_reports(document, document).has_regressions is False

    def test_a_dropped_rule_is_a_regression(self) -> None:
        report = compare_reports(coverage(), coverage(total_rules=9))
        assert report.has_regressions is True

    def test_an_added_rule_is_an_improvement(self) -> None:
        report = compare_reports(coverage(), coverage(total_rules=11))
        assert [change.key for change in report.improvements] == ["total_rules"]

    def test_a_newly_failing_gate_counts_as_a_regression(self) -> None:
        before = gate_document({"gate": "g", "passed": True, "enabled": True})
        after = gate_document({"gate": "g", "passed": False, "enabled": True})
        assert compare_reports(before, after).has_regressions is True

    def test_a_newly_passing_gate_is_not_a_regression(self) -> None:
        before = gate_document({"gate": "g", "passed": False, "enabled": True})
        after = gate_document({"gate": "g", "passed": True, "enabled": True})
        assert compare_reports(before, after).has_regressions is False

    def test_a_dropped_technique_is_reported(self) -> None:
        report = compare_reports(coverage(), coverage(technique_counts={}))
        change = next(entry for entry in report.sets if entry.key == "technique_counts")
        assert change.removed == ("T1059",)

    def test_a_new_untested_rule_is_reported(self) -> None:
        report = compare_reports(coverage(), coverage(untested_rules=["a"]))
        change = next(entry for entry in report.sets if entry.key == "untested_rules")
        assert change.added == ("a",)

    def test_test_totals_are_compared(self) -> None:
        before = {"tests": {"totals": {"failed": 0}}}
        after = {"tests": {"totals": {"failed": 2}}}
        report = compare_reports(before, after)
        assert [change.key for change in report.regressions] == ["failed"]

    def test_the_testing_section_name_is_also_accepted(self) -> None:
        before = {"testing": {"totals": {"failed": 2}}}
        after = {"testing": {"totals": {"failed": 0}}}
        assert compare_reports(before, after).improvements

    def test_a_bare_coverage_document_is_accepted(self) -> None:
        report = compare_reports({"total_rules": 5}, {"total_rules": 6})
        assert report.improvements[0].key == "total_rules"

    def test_a_document_without_coverage_is_noted(self) -> None:
        report = compare_reports({}, {})
        assert len(report.notes) == 2

    def test_a_valid_document_is_not_noted(self) -> None:
        assert compare_reports(coverage(), coverage()).notes == ()

    def test_labels_are_carried(self) -> None:
        report = compare_reports(
            coverage(), coverage(), baseline_label="old.json", current_label="new.json"
        )
        assert (report.baseline_label, report.current_label) == ("old.json", "new.json")

    def test_the_report_is_timestamped(self) -> None:
        assert compare_reports(coverage(), coverage()).generated_at.endswith("Z")

    def test_every_tracked_coverage_key_is_compared(self) -> None:
        report = compare_reports(coverage(), coverage())
        compared = {change.key for change in report.metrics}
        assert set(TRACKED_COVERAGE_KEYS) & compared

    def test_to_dict_reports_the_verdict(self) -> None:
        payload = compare_reports(coverage(), coverage(total_rules=9)).to_dict()
        assert payload["has_regressions"] is True

    def test_to_dict_counts_changes(self) -> None:
        payload = compare_reports(coverage(), coverage(total_rules=11)).to_dict()
        assert (payload["improvement_count"], payload["regression_count"]) == (1, 0)

    def test_to_dict_omits_unchanged_sets(self) -> None:
        payload = compare_reports(coverage(), coverage()).to_dict()
        assert payload["sets"] == []

    def test_to_dict_includes_gate_changes(self) -> None:
        before = gate_document({"gate": "g", "passed": True, "enabled": True})
        after = gate_document({"gate": "g", "passed": False, "enabled": True})
        payload = compare_reports(before, after).to_dict()
        assert payload["gate_changes"][0]["current"] == "failed"

    def test_to_dict_is_json_serialisable(self) -> None:
        payload = compare_reports(coverage(), coverage(total_rules=9)).to_dict()
        assert json.loads(json.dumps(payload))["baseline"] == "baseline"

    def test_an_empty_report_has_no_regressions(self) -> None:
        assert ComparisonReport().has_regressions is False


class TestLoadingFiles:
    def test_a_report_loads(self, tmp_path: Path) -> None:
        target = write_json(tmp_path / "report.json", {"total_rules": 1})
        assert load_report(target)["total_rules"] == 1

    def test_a_missing_file_is_a_report_error(self, tmp_path: Path) -> None:
        with pytest.raises(ReportError):
            load_report(tmp_path / "absent.json")

    def test_invalid_json_is_a_report_error(self, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        target.write_text("{not json", encoding="utf-8")
        with pytest.raises(ReportError, match="invalid JSON"):
            load_report(target)

    def test_a_non_object_root_is_refused(self, tmp_path: Path) -> None:
        target = write_json(tmp_path / "report.json", [1, 2, 3])
        with pytest.raises(ReportError, match="must be a JSON object"):
            load_report(target)

    def test_an_oversized_report_is_refused(self, tmp_path: Path) -> None:
        target = write_json(tmp_path / "report.json", {"a": "x" * 200})
        with pytest.raises(ReportError):
            load_report(target, max_bytes=10)

    def test_two_files_can_be_compared(self, tmp_path: Path) -> None:
        baseline = write_json(tmp_path / "baseline.json", coverage())
        current = write_json(tmp_path / "current.json", coverage(total_rules=9))
        assert compare_files(baseline, current).has_regressions is True

    def test_file_names_become_labels(self, tmp_path: Path) -> None:
        baseline = write_json(tmp_path / "baseline.json", coverage())
        current = write_json(tmp_path / "current.json", coverage())
        report = compare_files(baseline, current)
        assert (report.baseline_label, report.current_label) == ("baseline.json", "current.json")

    def test_comparing_a_file_with_itself_shows_no_change(self, tmp_path: Path) -> None:
        target = write_json(tmp_path / "report.json", coverage())
        assert compare_files(target, target).improvements == ()
