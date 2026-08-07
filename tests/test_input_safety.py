"""Cross-cutting behaviour on hostile input.

Every loader in this package reads files a contributor could get wrong or an
attacker could craft. The property under test here is uniform: hostile input is
refused with a deliberate :class:`SdelError`, never with a crash, a hang, or a
silent acceptance.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from conftest import make_event
from sigma_detection_engineering_lab import errors
from sigma_detection_engineering_lab.condition_parser import parse_condition
from sigma_detection_engineering_lab.config import LabConfig, load_config
from sigma_detection_engineering_lab.correlation_engine import parse_correlation, parse_timespan
from sigma_detection_engineering_lab.errors import (
    ConditionSyntaxError,
    MatcherError,
    RegexSafetyError,
    SdelError,
    UnsupportedConditionError,
    YamlSafetyError,
)
from sigma_detection_engineering_lab.event_matcher import DetectionMatcher
from sigma_detection_engineering_lab.event_model import SyntheticEvent
from sigma_detection_engineering_lab.fixture_loader import load_fixtures
from sigma_detection_engineering_lab.paths import safe_read_text, safe_resolve
from sigma_detection_engineering_lab.rule_loader import load_rules
from sigma_detection_engineering_lab.telemetry import build_catalog as build_telemetry
from sigma_detection_engineering_lab.yaml_loader import load_single_document

DELIBERATE = tuple(
    getattr(errors, name)
    for name in errors.__all__
    if isinstance(getattr(errors, name), type) and issubclass(getattr(errors, name), SdelError)
)


def event_with(**fields: object) -> SyntheticEvent:
    return make_event(fields=dict(fields))


def write_fixture(
    root: Path, filename: str, text: str, *, catalog_id: str = "SDEL-TST-001"
) -> Path:
    """Register one fixture file with a manifest so the loader will read it."""
    directory = root / "fixtures" / "rules" / catalog_id
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    target.write_text(text, encoding="utf-8", newline="\n")
    manifest = {
        "catalog_id": catalog_id,
        "positive_cases": [{"file": filename, "name": target.stem, "expected": "match"}],
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return target


class TestErrorHierarchy:
    def test_every_exported_error_derives_from_the_base(self) -> None:
        assert all(issubclass(error, SdelError) for error in DELIBERATE)

    def test_the_base_derives_from_exception(self) -> None:
        assert issubclass(SdelError, Exception)

    def test_the_hierarchy_is_not_empty(self) -> None:
        assert len(DELIBERATE) >= 15

    def test_matcher_errors_are_grouped(self) -> None:
        assert issubclass(RegexSafetyError, MatcherError)

    def test_no_error_derives_from_baseexception_directly(self) -> None:
        assert all(not issubclass(error, (KeyboardInterrupt, SystemExit)) for error in DELIBERATE)

    @pytest.mark.parametrize("error", DELIBERATE, ids=lambda e: e.__name__)
    def test_every_error_carries_a_message(self, error: type[SdelError]) -> None:
        assert str(error("something went wrong")) == "something went wrong"

    @pytest.mark.parametrize("error", DELIBERATE, ids=lambda e: e.__name__)
    def test_every_error_has_a_docstring(self, error: type[SdelError]) -> None:
        assert error.__doc__


class TestHostileYaml:
    @pytest.mark.parametrize(
        "text",
        [
            "!!python/object/apply:os.system ['echo hi']\n",
            "!!python/name:os.system\n",
            "value: !!binary AAAA\n",
            "value: !custom thing\n",
        ],
        ids=["python-apply", "python-name", "binary", "custom-tag"],
    )
    def test_a_forbidden_tag_is_refused(self, text: str) -> None:
        with pytest.raises(YamlSafetyError):
            load_single_document(text, source="hostile.yml")

    def test_an_alias_bomb_is_refused(self) -> None:
        text = (
            "a: &a [x, x, x, x, x, x, x, x, x]\n"
            "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
            "c: [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
        )
        with pytest.raises(YamlSafetyError):
            load_single_document(text, source="bomb.yml")

    def test_a_duplicate_key_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError):
            load_single_document("a: 1\na: 2\n", source="dup.yml")

    def test_deep_nesting_is_refused(self) -> None:
        text = "".join(f"{'  ' * index}k{index}:\n" for index in range(60)) + f"{'  ' * 60}v: 1\n"
        with pytest.raises(YamlSafetyError):
            load_single_document(text, source="deep.yml")

    def test_a_huge_scalar_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError):
            load_single_document(f"a: {'x' * 200_000}\n", source="big.yml")

    def test_refusal_is_fast(self) -> None:
        text = "".join(f"{'  ' * index}k{index}:\n" for index in range(80)) + f"{'  ' * 80}v: 1\n"
        started = time.monotonic()
        with pytest.raises(YamlSafetyError):
            load_single_document(text, source="deep.yml")
        assert time.monotonic() - started < 2.0

    def test_a_sound_document_still_loads(self) -> None:
        assert load_single_document("a: 1\n", source="ok.yml") == {"a": 1}


class TestHostileConditions:
    @pytest.mark.parametrize(
        "condition",
        [
            "selection | count() > 5",
            "selection | near other",
            "selection and count(field) > 3",
            "all of them | count() > 1",
        ],
    )
    def test_an_unsupported_construct_is_refused(self, condition: str) -> None:
        with pytest.raises((UnsupportedConditionError, ConditionSyntaxError)):
            parse_condition(condition)

    @pytest.mark.parametrize(
        "condition",
        ["selection and", "and selection", "(selection", "selection)", "", "   "],
    )
    def test_a_malformed_condition_is_refused(self, condition: str) -> None:
        with pytest.raises(SdelError):
            parse_condition(condition)

    def test_an_enormous_condition_is_refused(self) -> None:
        with pytest.raises(SdelError):
            parse_condition(" or ".join(["selection"] * 5000))

    def test_deeply_nested_parentheses_are_refused(self) -> None:
        with pytest.raises(SdelError):
            parse_condition("(" * 200 + "selection" + ")" * 200)

    def test_refusing_a_large_condition_is_fast(self) -> None:
        started = time.monotonic()
        with pytest.raises(SdelError):
            parse_condition(" or ".join(["selection"] * 20_000))
        assert time.monotonic() - started < 2.0


class TestHostileDetections:
    def test_a_catastrophic_regex_is_refused(self) -> None:
        detection = {"selection": {"CommandLine|re": "(a+)+$"}, "condition": "selection"}
        with pytest.raises(RegexSafetyError):
            DetectionMatcher(detection, source="hostile")

    def test_an_enormous_regex_is_refused(self) -> None:
        detection = {"selection": {"CommandLine|re": "a" * 20_000}, "condition": "selection"}
        with pytest.raises(RegexSafetyError):
            DetectionMatcher(detection, source="hostile")

    def test_an_invalid_regex_is_refused(self) -> None:
        detection = {"selection": {"CommandLine|re": "([unclosed"}, "condition": "selection"}
        with pytest.raises(MatcherError):
            DetectionMatcher(detection, source="hostile")

    def test_an_unknown_modifier_is_refused(self) -> None:
        detection = {"selection": {"Image|rot13": "x"}, "condition": "selection"}
        with pytest.raises(MatcherError):
            DetectionMatcher(detection, source="hostile")

    def test_a_malformed_cidr_is_refused(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "not-a-network"}, "condition": "selection"}
        with pytest.raises(MatcherError):
            DetectionMatcher(detection, source="hostile")

    def test_a_matcher_never_evaluates_input_as_code(self) -> None:
        detection = {
            "selection": {"Image": "__import__('os').system('echo hi')"},
            "condition": "selection",
        }
        matcher = DetectionMatcher(detection, source="ok")
        assert matcher.evaluate(event_with(Image="cmd.exe")).matched is False

    def test_a_code_shaped_value_still_matches_only_literally(self) -> None:
        payload = "__import__('os').system('echo hi')"
        detection = {"selection": {"Image": payload}, "condition": "selection"}
        matcher = DetectionMatcher(detection, source="ok")
        assert matcher.evaluate(event_with(Image=payload)).matched is True

    def test_a_huge_field_value_is_refused_rather_than_scanned(self) -> None:
        detection = {"selection": {"CommandLine|contains": "needle"}, "condition": "selection"}
        matcher = DetectionMatcher(detection, source="ok")
        with pytest.raises(MatcherError, match="exceeds the matcher input limit"):
            matcher.evaluate(event_with(CommandLine="x" * 500_000))

    def test_refusing_a_huge_field_value_is_fast(self) -> None:
        detection = {"selection": {"CommandLine|contains": "needle"}, "condition": "selection"}
        matcher = DetectionMatcher(detection, source="ok")
        started = time.monotonic()
        with pytest.raises(MatcherError):
            matcher.evaluate(event_with(CommandLine="x" * 2_000_000))
        assert time.monotonic() - started < 2.0


class TestHostileCorrelations:
    @pytest.mark.parametrize("value", ["", "5", "m", "5x", "-5m", "abc"])
    def test_a_malformed_timespan_is_refused(self, value: str) -> None:
        with pytest.raises(SdelError):
            parse_timespan(value)

    def test_an_unknown_correlation_type_is_refused(self) -> None:
        with pytest.raises(SdelError):
            parse_correlation({"type": "telepathy", "rules": ["a"], "timespan": "5m"})

    def test_a_correlation_without_rules_is_refused(self) -> None:
        with pytest.raises(SdelError):
            parse_correlation({"type": "event_count", "timespan": "5m"})

    def test_a_non_mapping_correlation_is_refused(self) -> None:
        with pytest.raises(SdelError):
            parse_correlation(["event_count"])  # type: ignore[arg-type]


class TestHostilePaths:
    def test_a_parent_traversal_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SdelError):
            safe_resolve(tmp_path, "../outside.txt")

    def test_an_absolute_escape_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SdelError):
            safe_resolve(tmp_path, "/etc/passwd")

    def test_an_embedded_traversal_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SdelError):
            safe_resolve(tmp_path, "rules/../../outside.txt")

    def test_an_oversized_file_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "big.txt"
        target.write_text("x" * 5000, encoding="utf-8")
        with pytest.raises(SdelError):
            safe_read_text(target, max_bytes=100)

    def test_invalid_utf8_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.txt"
        target.write_bytes(b"\xff\xfe\x00rules")
        with pytest.raises(SdelError):
            safe_read_text(target)

    def test_an_overlong_path_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SdelError):
            safe_resolve(tmp_path, "a" * 500, max_path_length=64)


class TestHostileProjectContent:
    def test_a_rule_file_with_a_python_tag_fails_to_load(self, tiny_project: Path) -> None:
        target = tiny_project / "rules" / "windows" / "hostile_rule.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("!!python/object/apply:os.system ['echo hi']\n", encoding="utf-8")
        config = load_config(tiny_project)
        result = load_rules(config)
        assert any("hostile_rule" in path for path, _ in result.failures)

    def test_one_hostile_rule_does_not_stop_the_others(self, tiny_project: Path) -> None:
        target = tiny_project / "rules" / "windows" / "hostile_rule.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("!!python/name:os.system\n", encoding="utf-8")
        result = load_rules(load_config(tiny_project))
        assert len(result.rules) >= 1

    def test_a_fixture_with_invalid_json_is_reported(self, tiny_project: Path) -> None:
        write_fixture(tiny_project, "bad.jsonl", "{not json\n")
        errors = load_fixtures(load_config(tiny_project)).errors
        assert any("invalid JSON" in message for _, message in errors)

    def test_a_fixture_marked_non_synthetic_is_reported(self, tiny_project: Path) -> None:
        record = {
            "event_id": "EVT-REAL",
            "timestamp": "2026-08-01T00:00:00Z",
            "synthetic": False,
            "fields": {"Image": "C:\\Windows\\System32\\cmd.exe"},
        }
        write_fixture(tiny_project, "real.jsonl", json.dumps(record) + "\n")
        errors = load_fixtures(load_config(tiny_project)).errors
        assert any("synthetic" in message for _, message in errors)

    def test_a_hostile_fixture_yields_no_cases(self, tiny_project: Path) -> None:
        write_fixture(tiny_project, "bad.jsonl", "{not json\n")
        assert load_fixtures(load_config(tiny_project)).cases == ()

    def test_a_malformed_config_is_refused(self, tiny_project: Path) -> None:
        (tiny_project / "config" / "default.config.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(SdelError):
            load_config(tiny_project)

    def test_a_config_with_a_missing_schema_version_is_refused(self, tiny_project: Path) -> None:
        (tiny_project / "config" / "default.config.json").write_text("{}", encoding="utf-8")
        with pytest.raises(SdelError):
            load_config(tiny_project)

    def test_a_malformed_telemetry_catalog_is_refused(self) -> None:
        with pytest.raises(SdelError):
            build_telemetry({"profiles": {"Bad Id!": {}}})


class TestNoSilentAcceptance:
    def test_an_empty_rule_directory_yields_an_empty_catalog(self, tiny_project: Path) -> None:
        for path in (tiny_project / "rules").rglob("*.yml"):
            path.unlink()
        assert load_rules(load_config(tiny_project)).rules == ()

    def test_a_rule_load_failure_is_recorded_rather_than_dropped(self, tiny_project: Path) -> None:
        target = tiny_project / "rules" / "windows" / "broken_rule.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("title: [unclosed\n", encoding="utf-8")
        assert load_rules(load_config(tiny_project)).failures

    def test_a_failure_carries_an_explanation(self, tiny_project: Path) -> None:
        target = tiny_project / "rules" / "windows" / "broken_rule.yml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("title: [unclosed\n", encoding="utf-8")
        assert all(message for _, message in load_rules(load_config(tiny_project)).failures)

    def test_the_real_project_loads_without_failures(self, real_config: LabConfig) -> None:
        assert load_rules(real_config).failures == ()
