"""Tests for correlation rule parsing and evaluation.

The engine implements four correlation types over ordered synthetic sequences.
Window inclusivity, grouping, and ordering are all documented choices, so they
are pinned here rather than left to inference.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from conftest import make_event
from sigma_detection_engineering_lab.correlation_engine import (
    CONDITION_OPERATORS,
    MAX_EVENTS,
    MAX_TIMESPAN_SECONDS,
    UNIT_SECONDS,
    CorrelationEngine,
    CorrelationType,
    CountCondition,
    format_timespan,
    parse_correlation,
    parse_count_condition,
    parse_timespan,
    synthetic_timeline,
)
from sigma_detection_engineering_lab.errors import CorrelationError
from sigma_detection_engineering_lab.event_matcher import RuleMatcher


def matcher_for(field: str, value: str) -> RuleMatcher:
    """A base rule matcher that fires when ``field`` equals ``value``."""
    return RuleMatcher(
        {"selection": {field: value}, "condition": "selection"},
        enforce_logsource=False,
    )


def engine(block: dict[str, Any], matchers: dict[str, RuleMatcher]) -> CorrelationEngine:
    return CorrelationEngine(parse_correlation(block), matchers)


class TestParseTimespan:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400), ("90s", 90)],
    )
    def test_valid_timespans(self, text: str, seconds: int) -> None:
        assert parse_timespan(text) == seconds

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        assert parse_timespan("  5m  ") == 300

    def test_bare_integer_is_refused_with_a_unit_hint(self) -> None:
        with pytest.raises(CorrelationError, match="missing a unit"):
            parse_timespan(300)

    @pytest.mark.parametrize("value", [None, 1.5, [], {}])
    def test_non_string_values_are_refused(self, value: object) -> None:
        with pytest.raises(CorrelationError):
            parse_timespan(value)

    @pytest.mark.parametrize("text", ["5x", "m5", "5 m", "", "-5m", "5.5m"])
    def test_malformed_timespans_are_refused(self, text: str) -> None:
        with pytest.raises(CorrelationError, match="invalid timespan"):
            parse_timespan(text)

    def test_zero_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="greater than zero"):
            parse_timespan("0s")

    def test_span_beyond_the_laboratory_limit_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="exceeds the laboratory limit"):
            parse_timespan("31d")

    def test_limit_is_thirty_days(self) -> None:
        assert MAX_TIMESPAN_SECONDS == 30 * 86_400

    def test_source_label_is_used_in_errors(self) -> None:
        with pytest.raises(CorrelationError, match="SDEL-COR-001"):
            parse_timespan("nope", source="SDEL-COR-001")

    def test_unit_table_is_consistent(self) -> None:
        assert UNIT_SECONDS == {"s": 1, "m": 60, "h": 3600, "d": 86400}


class TestFormatTimespan:
    @pytest.mark.parametrize(
        ("seconds", "text"),
        [(30, "30s"), (300, "5m"), (7200, "2h"), (86400, "1d"), (90, "90s"), (1, "1s")],
    )
    def test_rendering_is_compact(self, seconds: int, text: str) -> None:
        assert format_timespan(seconds) == text

    def test_round_trip_through_parse(self) -> None:
        assert parse_timespan(format_timespan(3600)) == 3600


class TestCountCondition:
    @pytest.mark.parametrize(
        ("operator", "threshold", "count", "expected"),
        [
            ("gt", 5, 6, True),
            ("gt", 5, 5, False),
            ("gte", 5, 5, True),
            ("gte", 5, 4, False),
            ("lt", 5, 4, True),
            ("lt", 5, 5, False),
            ("lte", 5, 5, True),
            ("lte", 5, 6, False),
            ("eq", 5, 5, True),
            ("eq", 5, 4, False),
        ],
    )
    def test_operator_semantics(
        self, operator: str, threshold: int, count: int, expected: bool
    ) -> None:
        assert CountCondition(operator, threshold).evaluate(count) is expected

    @pytest.mark.parametrize(
        ("operator", "rendered"),
        [("gt", "count > 5"), ("gte", "count >= 5"), ("lt", "count < 5"), ("eq", "count == 5")],
    )
    def test_render(self, operator: str, rendered: str) -> None:
        assert CountCondition(operator, 5).render() == rendered

    def test_supported_operator_set(self) -> None:
        assert frozenset({"gt", "gte", "lt", "lte", "eq"}) == CONDITION_OPERATORS


class TestParseCountCondition:
    def test_parses_a_single_operator(self) -> None:
        condition = parse_count_condition({"gte": 5})
        assert condition.operator == "gte" and condition.threshold == 5

    def test_field_key_is_permitted_alongside_the_operator(self) -> None:
        assert parse_count_condition({"gte": 5, "field": "User"}).threshold == 5

    def test_non_mapping_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must be a mapping"):
            parse_count_condition(5)

    def test_two_operators_are_refused(self) -> None:
        with pytest.raises(CorrelationError, match="exactly one comparison operator"):
            parse_count_condition({"gte": 5, "lt": 10})

    def test_no_operator_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="exactly one comparison operator"):
            parse_count_condition({"field": "User"})

    def test_unknown_key_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="unsupported condition key"):
            parse_count_condition({"gte": 5, "nope": 1})

    def test_non_integer_threshold_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must be an integer"):
            parse_count_condition({"gte": "five"})

    def test_boolean_threshold_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must be an integer"):
            parse_count_condition({"gte": True})

    def test_negative_threshold_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must not be negative"):
            parse_count_condition({"gte": -1})

    def test_zero_threshold_is_accepted(self) -> None:
        assert parse_count_condition({"gte": 0}).threshold == 0


class TestParseCorrelation:
    def test_event_count_block(self) -> None:
        definition = parse_correlation(
            {
                "type": "event_count",
                "rules": ["base"],
                "timespan": "5m",
                "group-by": ["User"],
                "condition": {"gte": 3},
            }
        )
        assert definition.type is CorrelationType.EVENT_COUNT
        assert definition.timespan_seconds == 300
        assert definition.group_by == ("User",)

    def test_value_count_requires_a_field(self) -> None:
        with pytest.raises(CorrelationError, match="value_count requires the field"):
            parse_correlation(
                {
                    "type": "value_count",
                    "rules": ["base"],
                    "timespan": "5m",
                    "condition": {"gte": 3},
                }
            )

    def test_value_count_field_may_live_in_the_condition(self) -> None:
        definition = parse_correlation(
            {
                "type": "value_count",
                "rules": ["base"],
                "timespan": "5m",
                "condition": {"gte": 3, "field": "TargetUser"},
            }
        )
        assert definition.value_field == "TargetUser"

    def test_value_count_field_may_be_top_level(self) -> None:
        definition = parse_correlation(
            {
                "type": "value_count",
                "rules": ["base"],
                "timespan": "5m",
                "field": "TargetUser",
                "condition": {"gte": 3},
            }
        )
        assert definition.value_field == "TargetUser"

    def test_temporal_requires_two_rules(self) -> None:
        with pytest.raises(CorrelationError, match="at least two referenced rules"):
            parse_correlation({"type": "temporal", "rules": ["a"], "timespan": "5m"})

    def test_temporal_ordered_requires_two_rules(self) -> None:
        with pytest.raises(CorrelationError, match="at least two referenced rules"):
            parse_correlation({"type": "temporal_ordered", "rules": ["a"], "timespan": "5m"})

    def test_temporal_with_two_rules_parses(self) -> None:
        definition = parse_correlation({"type": "temporal", "rules": ["a", "b"], "timespan": "5m"})
        assert definition.rules == ("a", "b")

    def test_unsupported_type_is_refused_by_name(self) -> None:
        with pytest.raises(CorrelationError, match="unsupported correlation type"):
            parse_correlation({"type": "value_change", "rules": ["a"], "timespan": "5m"})

    def test_unsupported_type_error_lists_the_supported_ones(self) -> None:
        with pytest.raises(CorrelationError, match="event_count"):
            parse_correlation({"type": "nonsense", "rules": ["a"], "timespan": "5m"})

    def test_missing_type_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="correlation type is required"):
            parse_correlation({"rules": ["a"], "timespan": "5m"})

    def test_missing_rules_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="at least one referenced rule"):
            parse_correlation({"type": "event_count", "timespan": "5m", "condition": {"gte": 1}})

    def test_missing_timespan_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="a timespan is required"):
            parse_correlation({"type": "event_count", "rules": ["a"], "condition": {"gte": 1}})

    def test_counting_type_requires_a_condition(self) -> None:
        with pytest.raises(CorrelationError, match="requires a condition"):
            parse_correlation({"type": "event_count", "rules": ["a"], "timespan": "5m"})

    def test_non_mapping_block_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must be a mapping"):
            parse_correlation([])  # type: ignore[arg-type]

    def test_single_rule_string_is_accepted(self) -> None:
        definition = parse_correlation(
            {"type": "event_count", "rules": "base", "timespan": "5m", "condition": {"gte": 1}}
        )
        assert definition.rules == ("base",)

    def test_underscore_group_by_spelling_is_accepted(self) -> None:
        definition = parse_correlation(
            {
                "type": "event_count",
                "rules": ["a"],
                "timespan": "5m",
                "group_by": ["User"],
                "condition": {"gte": 1},
            }
        )
        assert definition.group_by == ("User",)

    def test_generate_flag_is_recorded(self) -> None:
        definition = parse_correlation(
            {
                "type": "event_count",
                "rules": ["a"],
                "timespan": "5m",
                "condition": {"gte": 1},
                "generate": True,
            }
        )
        assert definition.generate is True

    def test_to_dict_is_json_friendly(self) -> None:
        payload = parse_correlation(
            {
                "type": "event_count",
                "rules": ["a"],
                "timespan": "5m",
                "condition": {"gte": 2},
            }
        ).to_dict()
        assert payload["type"] == "event_count" and payload["timespan"] == "5m"
        assert payload["condition"] == "count >= 2"


class TestParseAliases:
    def test_aliases_are_parsed(self) -> None:
        definition = parse_correlation(
            {
                "type": "temporal",
                "rules": ["a", "b"],
                "timespan": "5m",
                "group-by": ["path"],
                "aliases": {"path": {"a": "Image", "b": "TargetFilename"}},
            }
        )
        assert definition.aliases["path"]["a"] == "Image"

    def test_alias_naming_an_unlisted_rule_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="does not list"):
            parse_correlation(
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "aliases": {"path": {"c": "Image"}},
                }
            )

    def test_alias_body_must_be_a_mapping(self) -> None:
        with pytest.raises(CorrelationError, match="map each rule to a field"):
            parse_correlation(
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "aliases": {"path": "Image"},
                }
            )

    def test_alias_field_must_be_a_string(self) -> None:
        with pytest.raises(CorrelationError, match="field name must be a string"):
            parse_correlation(
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "aliases": {"path": {"a": 5}},
                }
            )

    def test_aliases_block_must_be_a_mapping(self) -> None:
        with pytest.raises(CorrelationError, match="aliases must be a mapping"):
            parse_correlation(
                {"type": "temporal", "rules": ["a", "b"], "timespan": "5m", "aliases": []}
            )

    def test_resolve_field_returns_the_name_when_not_an_alias(self) -> None:
        definition = parse_correlation({"type": "temporal", "rules": ["a", "b"], "timespan": "5m"})
        assert definition.resolve_field("User", {"a"}) == "User"

    def test_resolve_field_uses_the_matched_rule(self) -> None:
        definition = parse_correlation(
            {
                "type": "temporal",
                "rules": ["a", "b"],
                "timespan": "5m",
                "aliases": {"path": {"a": "Image", "b": "TargetFilename"}},
            }
        )
        assert definition.resolve_field("path", {"b"}) == "TargetFilename"

    def test_resolve_field_returns_none_for_an_unmapped_rule(self) -> None:
        definition = parse_correlation(
            {
                "type": "temporal",
                "rules": ["a", "b"],
                "timespan": "5m",
                "aliases": {"path": {"a": "Image"}},
            }
        )
        assert definition.resolve_field("path", {"b"}) is None


class TestEngineConstruction:
    def test_unresolvable_rule_is_refused(self) -> None:
        definition = parse_correlation(
            {"type": "event_count", "rules": ["missing"], "timespan": "5m", "condition": {"gte": 1}}
        )
        with pytest.raises(CorrelationError, match="not resolvable"):
            CorrelationEngine(definition, {})

    def test_error_lists_available_matchers(self) -> None:
        definition = parse_correlation(
            {"type": "event_count", "rules": ["missing"], "timespan": "5m", "condition": {"gte": 1}}
        )
        with pytest.raises(CorrelationError, match="present"):
            CorrelationEngine(definition, {"present": matcher_for("Image", "a.exe")})

    def test_oversized_sequence_is_refused(self) -> None:
        built = engine(
            {"type": "event_count", "rules": ["a"], "timespan": "5m", "condition": {"gte": 1}},
            {"a": matcher_for("Image", "a.exe")},
        )
        events = [make_event(f"E{index}") for index in range(MAX_EVENTS + 1)]
        with pytest.raises(CorrelationError, match="exceeds limit"):
            built.evaluate(events)


class TestEventCount:
    def build(self, threshold: int = 3, timespan: str = "5m") -> CorrelationEngine:
        return engine(
            {
                "type": "event_count",
                "rules": ["failed"],
                "timespan": timespan,
                "group-by": ["User"],
                "condition": {"gte": threshold},
            },
            {"failed": matcher_for("Status", "failure")},
        )

    def events(self, count: int, *, user: str = "u1", step: int = 10) -> list[Any]:
        return [
            make_event(
                f"E{index}",
                fields={"Status": "failure", "User": user},
                offset_seconds=index * step,
            )
            for index in range(count)
        ]

    def test_threshold_met_matches(self) -> None:
        assert self.build().evaluate(self.events(3)).matched is True

    def test_below_threshold_does_not_match(self) -> None:
        assert self.build().evaluate(self.events(2)).matched is False

    def test_above_threshold_matches(self) -> None:
        assert self.build().evaluate(self.events(5)).matched is True

    def test_events_outside_the_window_do_not_count(self) -> None:
        built = self.build(threshold=3, timespan="30s")
        events = self.events(3, step=60)
        assert built.evaluate(events).matched is False

    def test_window_is_inclusive_at_the_upper_bound(self) -> None:
        built = self.build(threshold=2, timespan="30s")
        events = [
            make_event("E0", fields={"Status": "failure", "User": "u1"}, offset_seconds=0),
            make_event("E1", fields={"Status": "failure", "User": "u1"}, offset_seconds=30),
        ]
        assert built.evaluate(events).matched is True

    def test_window_excludes_one_second_past_the_bound(self) -> None:
        built = self.build(threshold=2, timespan="30s")
        events = [
            make_event("E0", fields={"Status": "failure", "User": "u1"}, offset_seconds=0),
            make_event("E1", fields={"Status": "failure", "User": "u1"}, offset_seconds=31),
        ]
        assert built.evaluate(events).matched is False

    def test_groups_are_counted_independently(self) -> None:
        built = self.build(threshold=3)
        events = self.events(2, user="u1") + self.events(2, user="u2")
        assert built.evaluate(events).matched is False

    def test_one_group_reaching_the_threshold_matches(self) -> None:
        built = self.build(threshold=2)
        events = self.events(1, user="u1") + self.events(2, user="u2")
        assert built.evaluate(events).matched is True

    def test_matching_group_is_reported(self) -> None:
        result = self.build(threshold=2).evaluate(self.events(2, user="alice"))
        assert result.matching_group == "alice"

    def test_grouping_is_case_insensitive(self) -> None:
        built = self.build(threshold=2)
        events = [
            make_event("E0", fields={"Status": "failure", "User": "Alice"}),
            make_event("E1", fields={"Status": "failure", "User": "alice"}, offset_seconds=5),
        ]
        assert built.evaluate(events).matched is True

    def test_events_not_matching_the_base_rule_are_ignored(self) -> None:
        built = self.build(threshold=2)
        events = [*self.events(1), make_event("X", fields={"Status": "success", "User": "u1"})]
        assert built.evaluate(events).matched is False

    def test_event_missing_the_group_field_is_skipped_and_counted(self) -> None:
        built = self.build(threshold=2)
        events = [*self.events(1), make_event("X", fields={"Status": "failure"})]
        result = built.evaluate(events)
        assert result.events_skipped == 1 and result.matched is False

    def test_result_reports_events_considered(self) -> None:
        assert self.build().evaluate(self.events(4)).events_considered == 4

    def test_result_reports_group_count(self) -> None:
        events = self.events(1, user="a") + self.events(1, user="b")
        assert self.build().evaluate(events).groups_evaluated == 2

    def test_result_reports_the_best_observed_value_on_failure(self) -> None:
        assert self.build(threshold=9).evaluate(self.events(4)).observed_value == 4

    def test_explanation_names_the_correlation_type(self) -> None:
        result = self.build().evaluate(self.events(3))
        assert any("correlation type: event_count" in line for line in result.explanation)

    def test_explanation_reports_the_timespan(self) -> None:
        result = self.build().evaluate(self.events(3))
        assert any("timespan: 5m" in line for line in result.explanation)

    def test_empty_sequence_does_not_match(self) -> None:
        assert self.build().evaluate([]).matched is False

    def test_ungrouped_correlation_pools_every_event(self) -> None:
        built = engine(
            {
                "type": "event_count",
                "rules": ["failed"],
                "timespan": "5m",
                "condition": {"gte": 2},
            },
            {"failed": matcher_for("Status", "failure")},
        )
        events = [
            make_event("E0", fields={"Status": "failure", "User": "a"}),
            make_event("E1", fields={"Status": "failure", "User": "b"}, offset_seconds=5),
        ]
        result = built.evaluate(events)
        assert result.matched is True and result.matching_group == "(all events)"

    def test_lt_condition_matches_a_quiet_window(self) -> None:
        built = engine(
            {
                "type": "event_count",
                "rules": ["failed"],
                "timespan": "5m",
                "condition": {"lt": 2},
            },
            {"failed": matcher_for("Status", "failure")},
        )
        assert built.evaluate(self.events(1)).matched is True

    def test_to_dict_round_trips_the_result(self) -> None:
        payload = self.build().evaluate(self.events(3)).to_dict()
        assert payload["matched"] is True
        assert payload["correlation_type"] == "event_count"
        assert isinstance(payload["explanation"], list)


class TestValueCount:
    def build(self, threshold: int = 3) -> CorrelationEngine:
        return engine(
            {
                "type": "value_count",
                "rules": ["probe"],
                "timespan": "5m",
                "group-by": ["SourceHost"],
                "field": "TargetUser",
                "condition": {"gte": threshold},
            },
            {"probe": matcher_for("Action", "probe")},
        )

    def events(self, users: list[str]) -> list[Any]:
        return [
            make_event(
                f"E{index}",
                fields={"Action": "probe", "SourceHost": "h1", "TargetUser": user},
                offset_seconds=index * 5,
            )
            for index, user in enumerate(users)
        ]

    def test_distinct_values_reaching_the_threshold_match(self) -> None:
        assert self.build().evaluate(self.events(["a", "b", "c"])).matched is True

    def test_repeated_values_count_once(self) -> None:
        assert self.build().evaluate(self.events(["a", "a", "a"])).matched is False

    def test_distinct_count_is_case_insensitive(self) -> None:
        assert self.build(threshold=2).evaluate(self.events(["a", "A"])).matched is False

    def test_events_missing_the_counted_field_are_ignored(self) -> None:
        built = self.build(threshold=2)
        events = [
            *self.events(["a"]),
            make_event("X", fields={"Action": "probe", "SourceHost": "h1"}, offset_seconds=20),
        ]
        assert built.evaluate(events).matched is False

    def test_observed_value_reports_the_distinct_count(self) -> None:
        assert self.build(threshold=9).evaluate(self.events(["a", "b"])).observed_value == 2

    def test_distinct_values_outside_the_window_do_not_combine(self) -> None:
        built = engine(
            {
                "type": "value_count",
                "rules": ["probe"],
                "timespan": "10s",
                "group-by": ["SourceHost"],
                "field": "TargetUser",
                "condition": {"gte": 2},
            },
            {"probe": matcher_for("Action", "probe")},
        )
        events = [
            make_event("E0", fields={"Action": "probe", "SourceHost": "h", "TargetUser": "a"}),
            make_event(
                "E1",
                fields={"Action": "probe", "SourceHost": "h", "TargetUser": "b"},
                offset_seconds=60,
            ),
        ]
        assert built.evaluate(events).matched is False

    def test_explanation_names_the_counted_field(self) -> None:
        result = self.build().evaluate(self.events(["a"]))
        assert any("TargetUser" in line for line in result.explanation)


class TestTemporal:
    def build(self, timespan: str = "5m") -> CorrelationEngine:
        return engine(
            {
                "type": "temporal",
                "rules": ["stage", "execute"],
                "timespan": timespan,
                "group-by": ["Host"],
            },
            {
                "stage": matcher_for("Action", "stage"),
                "execute": matcher_for("Action", "execute"),
            },
        )

    def test_both_rules_in_the_window_match(self) -> None:
        events = [
            make_event("E0", fields={"Action": "stage", "Host": "h"}),
            make_event("E1", fields={"Action": "execute", "Host": "h"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).matched is True

    def test_order_does_not_matter_for_plain_temporal(self) -> None:
        events = [
            make_event("E0", fields={"Action": "execute", "Host": "h"}),
            make_event("E1", fields={"Action": "stage", "Host": "h"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).matched is True

    def test_only_one_rule_present_does_not_match(self) -> None:
        events = [make_event("E0", fields={"Action": "stage", "Host": "h"})]
        assert self.build().evaluate(events).matched is False

    def test_rules_in_different_groups_do_not_combine(self) -> None:
        events = [
            make_event("E0", fields={"Action": "stage", "Host": "h1"}),
            make_event("E1", fields={"Action": "execute", "Host": "h2"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).matched is False

    def test_rules_beyond_the_window_do_not_combine(self) -> None:
        events = [
            make_event("E0", fields={"Action": "stage", "Host": "h"}),
            make_event("E1", fields={"Action": "execute", "Host": "h"}, offset_seconds=600),
        ]
        assert self.build(timespan="30s").evaluate(events).matched is False

    def test_one_event_satisfying_both_rules_counts_for_both(self) -> None:
        built = engine(
            {"type": "temporal", "rules": ["a", "b"], "timespan": "5m"},
            {"a": matcher_for("X", "1"), "b": matcher_for("Y", "2")},
        )
        assert built.evaluate([make_event("E0", fields={"X": "1", "Y": "2"})]).matched is True

    def test_observed_value_counts_distinct_rules_present(self) -> None:
        events = [make_event("E0", fields={"Action": "stage", "Host": "h"})]
        assert self.build().evaluate(events).observed_value == 1

    def test_explanation_reports_the_rule_ratio(self) -> None:
        events = [make_event("E0", fields={"Action": "stage", "Host": "h"})]
        result = self.build().evaluate(events)
        assert any("1/2 referenced rules" in line for line in result.explanation)


class TestTemporalOrdered:
    def build(self) -> CorrelationEngine:
        return engine(
            {
                "type": "temporal_ordered",
                "rules": ["first", "second", "third"],
                "timespan": "5m",
                "group-by": ["Host"],
            },
            {
                "first": matcher_for("Step", "1"),
                "second": matcher_for("Step", "2"),
                "third": matcher_for("Step", "3"),
            },
        )

    def sequence(self, steps: list[str]) -> list[Any]:
        return [
            make_event(f"E{index}", fields={"Step": step, "Host": "h"}, offset_seconds=index * 10)
            for index, step in enumerate(steps)
        ]

    def test_correct_order_matches(self) -> None:
        assert self.build().evaluate(self.sequence(["1", "2", "3"])).matched is True

    def test_reverse_order_does_not_match(self) -> None:
        assert self.build().evaluate(self.sequence(["3", "2", "1"])).matched is False

    def test_out_of_order_middle_step_does_not_match(self) -> None:
        assert self.build().evaluate(self.sequence(["1", "3", "2"])).matched is False

    def test_extra_events_between_steps_are_tolerated(self) -> None:
        assert self.build().evaluate(self.sequence(["1", "1", "2", "1", "3"])).matched is True

    def test_missing_final_step_does_not_match(self) -> None:
        assert self.build().evaluate(self.sequence(["1", "2"])).matched is False

    def test_observed_value_is_the_ordered_prefix_length(self) -> None:
        assert self.build().evaluate(self.sequence(["1", "2"])).observed_value == 2

    def test_prefix_of_zero_when_the_first_step_never_appears(self) -> None:
        assert self.build().evaluate(self.sequence(["2", "3"])).observed_value == 0

    def test_ordering_is_by_timestamp_not_input_order(self) -> None:
        events = [
            make_event("E2", fields={"Step": "3", "Host": "h"}, offset_seconds=20),
            make_event("E0", fields={"Step": "1", "Host": "h"}, offset_seconds=0),
            make_event("E1", fields={"Step": "2", "Host": "h"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).matched is True

    def test_identical_timestamps_are_ordered_by_event_id(self) -> None:
        events = [
            make_event("E3", fields={"Step": "3", "Host": "h"}),
            make_event("E1", fields={"Step": "1", "Host": "h"}),
            make_event("E2", fields={"Step": "2", "Host": "h"}),
        ]
        assert self.build().evaluate(events).matched is True

    def test_explanation_reports_the_ordered_prefix(self) -> None:
        result = self.build().evaluate(self.sequence(["1", "2"]))
        assert any("ordered prefix" in line for line in result.explanation)


class TestAliasGrouping:
    def build(self) -> CorrelationEngine:
        return engine(
            {
                "type": "temporal_ordered",
                "rules": ["write", "run"],
                "timespan": "5m",
                "group-by": ["path"],
                "aliases": {"path": {"write": "TargetFilename", "run": "Image"}},
            },
            {
                "write": matcher_for("Action", "write"),
                "run": matcher_for("Action", "run"),
            },
        )

    def test_alias_groups_differently_named_fields(self) -> None:
        events = [
            make_event(
                "E0",
                fields={"Action": "write", "TargetFilename": "C:\\tmp\\x.exe"},
            ),
            make_event(
                "E1",
                fields={"Action": "run", "Image": "C:\\tmp\\x.exe"},
                offset_seconds=10,
            ),
        ]
        assert self.build().evaluate(events).matched is True

    def test_different_alias_values_land_in_different_groups(self) -> None:
        events = [
            make_event("E0", fields={"Action": "write", "TargetFilename": "a.exe"}),
            make_event("E1", fields={"Action": "run", "Image": "b.exe"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).matched is False

    def test_event_missing_its_aliased_field_is_skipped(self) -> None:
        events = [
            make_event("E0", fields={"Action": "write"}),
            make_event("E1", fields={"Action": "run", "Image": "b.exe"}, offset_seconds=10),
        ]
        assert self.build().evaluate(events).events_skipped == 1


class TestSyntheticTimeline:
    def test_generates_the_requested_count(self) -> None:
        assert len(synthetic_timeline(5)) == 5

    def test_timestamps_ascend_by_the_step(self) -> None:
        stamps = synthetic_timeline(3, step_seconds=60)
        assert (stamps[1] - stamps[0]).total_seconds() == 60

    def test_default_epoch_is_fixed(self) -> None:
        assert synthetic_timeline(1) == synthetic_timeline(1)

    def test_every_timestamp_is_timezone_aware(self) -> None:
        assert all(stamp.tzinfo is not None for stamp in synthetic_timeline(3))

    def test_custom_start_is_honoured(self) -> None:
        start = datetime(2030, 5, 1, tzinfo=UTC)
        assert synthetic_timeline(1, start=start)[0] == start

    def test_naive_start_is_treated_as_utc(self) -> None:
        stamps = synthetic_timeline(1, start=datetime(2030, 5, 1))  # noqa: DTZ001 - naive on purpose
        assert stamps[0].tzinfo is UTC

    def test_zero_count_yields_no_timestamps(self) -> None:
        assert synthetic_timeline(0) == []

    def test_negative_count_is_refused(self) -> None:
        with pytest.raises(CorrelationError, match="must not be negative"):
            synthetic_timeline(-1)
