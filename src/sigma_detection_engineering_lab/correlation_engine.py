"""Correlation rule evaluation over synthetic event sequences.

Four Sigma correlation types are implemented: ``event_count``, ``value_count``,
``temporal``, and ``temporal_ordered``. Anything else is refused.

Documented semantics, chosen explicitly where the specification leaves latitude:

* **Window.** A sliding window anchored on each event in a group, inclusive at
  both ends: an event at ``t`` and one at exactly ``t + timespan`` are in the
  same window. A rule matches if *any* window satisfies the condition.
* **Grouping.** Events are partitioned by the tuple of ``group-by`` field values.
  An event missing any ``group-by`` field cannot be attributed to a group and is
  excluded, which is recorded in the result rather than passed over in silence.
* **Aliases.** A ``group-by`` entry may name an alias declared in ``aliases``,
  which maps each referenced rule to the field carrying that value in its own
  events. This is what lets a file-creation event and a process-creation event
  group on the same path when one calls it ``TargetFilename`` and the other
  ``Image``.
* **Ordering.** ``temporal_ordered`` requires the referenced rules to appear as a
  time-ordered subsequence. Matching is greedy: the earliest event satisfying the
  next expected rule is consumed.
* **Ties.** Events with identical timestamps are ordered by event identifier so
  evaluation is deterministic regardless of input order.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Final

from sigma_detection_engineering_lab.errors import CorrelationError
from sigma_detection_engineering_lab.event_matcher import RuleMatcher
from sigma_detection_engineering_lab.event_model import SENTINEL_MISSING, SyntheticEvent

TIMESPAN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(?P<value>\d{1,6})(?P<unit>[smhd])$")

UNIT_SECONDS: Final[dict[str, int]] = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}

CONDITION_OPERATORS: Final[frozenset[str]] = frozenset({"gt", "gte", "lt", "lte", "eq"})

MAX_TIMESPAN_SECONDS: Final[int] = 30 * 86_400
MAX_EVENTS: Final[int] = 10_000


class CorrelationType(str, Enum):
    """Supported Sigma correlation types."""

    EVENT_COUNT = "event_count"
    VALUE_COUNT = "value_count"
    TEMPORAL = "temporal"
    TEMPORAL_ORDERED = "temporal_ordered"

    def __str__(self) -> str:
        return self.value


def parse_timespan(value: object, *, source: str = "correlation.timespan") -> int:
    """Parse a Sigma timespan such as ``30s``, ``5m``, ``2h``, or ``1d``.

    Returns:
        The timespan in whole seconds.

    Raises:
        CorrelationError: if the format is wrong or the span is out of range.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        raise CorrelationError(
            f"{source}: timespan {value!r} is missing a unit; use for example '30s', '5m', "
            "'2h', or '1d'"
        )
    if not isinstance(value, str):
        raise CorrelationError(f"{source}: timespan must be a string, got {type(value).__name__}")
    match = TIMESPAN_PATTERN.match(value.strip())
    if not match:
        raise CorrelationError(
            f"{source}: invalid timespan {value!r}; expected <number><s|m|h|d>, e.g. '5m'"
        )
    seconds = int(match.group("value")) * UNIT_SECONDS[match.group("unit")]
    if seconds <= 0:
        raise CorrelationError(f"{source}: timespan must be greater than zero, got {value!r}")
    if seconds > MAX_TIMESPAN_SECONDS:
        raise CorrelationError(
            f"{source}: timespan {value!r} exceeds the laboratory limit of "
            f"{MAX_TIMESPAN_SECONDS} seconds"
        )
    return seconds


def format_timespan(seconds: int) -> str:
    """Render seconds back into the most compact Sigma timespan form."""
    for unit in ("d", "h", "m"):
        size = UNIT_SECONDS[unit]
        if seconds % size == 0 and seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


@dataclass(frozen=True)
class CountCondition:
    """The ``condition`` block of a counting correlation rule."""

    operator: str
    threshold: int

    def evaluate(self, count: int) -> bool:
        if self.operator == "gt":
            return count > self.threshold
        if self.operator == "gte":
            return count >= self.threshold
        if self.operator == "lt":
            return count < self.threshold
        if self.operator == "lte":
            return count <= self.threshold
        return count == self.threshold

    def render(self) -> str:
        symbols = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "=="}
        return f"count {symbols[self.operator]} {self.threshold}"


def parse_count_condition(
    value: object,
    *,
    source: str = "correlation.condition",
) -> CountCondition:
    """Parse a counting condition such as ``{gte: 5}``.

    Raises:
        CorrelationError: if the block is missing, ambiguous, or uses an
            unsupported operator.
    """
    if not isinstance(value, Mapping):
        raise CorrelationError(
            f"{source}: condition must be a mapping such as {{gte: 5}}, got {type(value).__name__}"
        )
    operators = [key for key in value if key in CONDITION_OPERATORS]
    extra = [key for key in value if key not in CONDITION_OPERATORS and key != "field"]
    if extra:
        raise CorrelationError(
            f"{source}: unsupported condition key(s) {', '.join(sorted(map(str, extra)))}; "
            f"supported operators: {', '.join(sorted(CONDITION_OPERATORS))}"
        )
    if len(operators) != 1:
        raise CorrelationError(
            f"{source}: exactly one comparison operator is required, found {len(operators)}"
        )
    operator = str(operators[0])
    threshold = value[operator]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise CorrelationError(f"{source}.{operator}: threshold must be an integer")
    if threshold < 0:
        raise CorrelationError(f"{source}.{operator}: threshold must not be negative")
    return CountCondition(operator=operator, threshold=threshold)


@dataclass(frozen=True)
class CorrelationDefinition:
    """A parsed Sigma ``correlation`` block."""

    type: CorrelationType
    rules: tuple[str, ...]
    timespan_seconds: int
    timespan_text: str
    group_by: tuple[str, ...] = ()
    condition: CountCondition | None = None
    value_field: str | None = None
    aliases: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    generate: bool = False

    def resolve_field(self, name: str, rules: Iterable[str]) -> str | None:
        """Resolve a ``group-by`` name to a concrete field for a matched event.

        Args:
            name: The ``group-by`` entry, which may be an alias.
            rules: The referenced rules the event matched.

        Returns:
            The field to read, or ``None`` when ``name`` is an alias that declares
            no field for any rule the event matched.
        """
        alias = self.aliases.get(name)
        if alias is None:
            return name
        for rule in self.rules:
            if rule in rules and rule in alias:
                return alias[rule]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "rules": list(self.rules),
            "timespan": self.timespan_text,
            "timespan_seconds": self.timespan_seconds,
            "group_by": list(self.group_by),
            "condition": self.condition.render() if self.condition else None,
            "value_field": self.value_field,
            "aliases": {alias: dict(mapping) for alias, mapping in sorted(self.aliases.items())},
        }


def _string_sequence(value: object, source: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    raise CorrelationError(f"{source}: expected a string or list of strings")


def parse_correlation(
    block: Mapping[str, Any],
    *,
    source: str = "correlation",
) -> CorrelationDefinition:
    """Parse and validate a Sigma ``correlation`` block.

    Raises:
        CorrelationError: if the type is unsupported or a required key is missing.
    """
    if not isinstance(block, Mapping):
        raise CorrelationError(f"{source}: correlation block must be a mapping")

    raw_type = block.get("type")
    if not isinstance(raw_type, str):
        raise CorrelationError(f"{source}.type: correlation type is required")
    try:
        correlation_type = CorrelationType(raw_type.strip().lower())
    except ValueError as exc:
        supported = ", ".join(item.value for item in CorrelationType)
        raise CorrelationError(
            f"{source}.type: unsupported correlation type {raw_type!r}; "
            f"this laboratory implements: {supported}"
        ) from exc

    rules = _string_sequence(block.get("rules"), f"{source}.rules")
    if not rules:
        raise CorrelationError(f"{source}.rules: at least one referenced rule is required")

    if "timespan" not in block:
        raise CorrelationError(f"{source}.timespan: a timespan is required")
    timespan_text = str(block["timespan"]).strip()
    timespan_seconds = parse_timespan(block["timespan"], source=f"{source}.timespan")

    group_by = _string_sequence(block.get("group-by", block.get("group_by")), f"{source}.group-by")

    condition: CountCondition | None = None
    value_field: str | None = None

    if correlation_type in (CorrelationType.EVENT_COUNT, CorrelationType.VALUE_COUNT):
        if "condition" not in block:
            raise CorrelationError(
                f"{source}.condition: {correlation_type} requires a condition such as {{gte: 5}}"
            )
        condition = parse_count_condition(block["condition"], source=f"{source}.condition")

    if correlation_type is CorrelationType.VALUE_COUNT:
        raw_condition = block.get("condition")
        candidate = block.get("field")
        if candidate is None and isinstance(raw_condition, Mapping):
            candidate = raw_condition.get("field")
        if not isinstance(candidate, str) or not candidate.strip():
            raise CorrelationError(
                f"{source}.field: value_count requires the field whose distinct values are counted"
            )
        value_field = candidate.strip()

    is_temporal = correlation_type in (CorrelationType.TEMPORAL, CorrelationType.TEMPORAL_ORDERED)
    if is_temporal and len(rules) < 2:
        raise CorrelationError(
            f"{source}.rules: {correlation_type} requires at least two referenced rules"
        )

    aliases = _parse_aliases(block.get("aliases"), rules, source=f"{source}.aliases")

    return CorrelationDefinition(
        type=correlation_type,
        rules=rules,
        timespan_seconds=timespan_seconds,
        timespan_text=timespan_text or format_timespan(timespan_seconds),
        group_by=group_by,
        condition=condition,
        value_field=value_field,
        aliases=aliases,
        generate=bool(block.get("generate", False)),
    )


def _parse_aliases(
    value: object,
    rules: Sequence[str],
    *,
    source: str,
) -> dict[str, dict[str, str]]:
    """Parse the ``aliases`` block, checking every referenced rule is known.

    An alias naming a rule the correlation does not reference is a typo that would
    otherwise silently produce an ungroupable event, so it is refused here.
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CorrelationError(f"{source}: aliases must be a mapping")

    known = set(rules)
    parsed: dict[str, dict[str, str]] = {}
    for alias, mapping in value.items():
        label = f"{source}.{alias}"
        if not isinstance(mapping, Mapping):
            raise CorrelationError(f"{label}: an alias must map each rule to a field name")
        resolved: dict[str, str] = {}
        for rule_name, field_name in mapping.items():
            if str(rule_name) not in known:
                raise CorrelationError(
                    f"{label}: references rule {rule_name!r}, which this correlation does "
                    f"not list; referenced rules are: {', '.join(rules)}"
                )
            if not isinstance(field_name, str) or not field_name.strip():
                raise CorrelationError(f"{label}.{rule_name}: field name must be a string")
            resolved[str(rule_name)] = field_name.strip()
        parsed[str(alias)] = resolved
    return parsed


@dataclass(frozen=True)
class CorrelationResult:
    """Outcome of evaluating a correlation rule against one event sequence."""

    matched: bool
    correlation_type: str
    groups_evaluated: int = 0
    events_considered: int = 0
    events_skipped: int = 0
    matching_group: str | None = None
    observed_value: int | None = None
    explanation: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "correlation_type": self.correlation_type,
            "groups_evaluated": self.groups_evaluated,
            "events_considered": self.events_considered,
            "events_skipped": self.events_skipped,
            "matching_group": self.matching_group,
            "observed_value": self.observed_value,
            "explanation": list(self.explanation),
        }


@dataclass
class _Annotated:
    """An event paired with the referenced base rules it satisfies."""

    event: SyntheticEvent
    rules: frozenset[str]
    group: tuple[str, ...]


class CorrelationEngine:
    """Evaluates one correlation definition against sequences of synthetic events."""

    def __init__(
        self,
        definition: CorrelationDefinition,
        base_matchers: Mapping[str, RuleMatcher],
        *,
        source: str = "correlation",
    ) -> None:
        missing = [name for name in definition.rules if name not in base_matchers]
        if missing:
            available = ", ".join(sorted(base_matchers)) or "(none)"
            raise CorrelationError(
                f"{source}: referenced rule(s) not resolvable: {', '.join(missing)}; "
                f"available: {available}"
            )
        self.definition = definition
        self.base_matchers = dict(base_matchers)
        self.source = source

    def evaluate(self, events: Sequence[SyntheticEvent]) -> CorrelationResult:
        """Return whether the correlation fires over ``events``.

        Raises:
            CorrelationError: if the sequence exceeds the laboratory event limit.
        """
        if len(events) > MAX_EVENTS:
            raise CorrelationError(
                f"{self.source}: sequence of {len(events)} events exceeds limit {MAX_EVENTS}"
            )

        annotated, skipped = self._annotate(events)
        groups = self._group(annotated)
        explanation: list[str] = [
            f"correlation type: {self.definition.type}",
            f"timespan: {self.definition.timespan_text} ({self.definition.timespan_seconds}s)",
            f"referenced rules: {', '.join(self.definition.rules)}",
            f"group-by: {', '.join(self.definition.group_by) or '(none)'}",
            f"events considered: {len(annotated)}, skipped: {skipped}",
            f"groups: {len(groups)}",
        ]

        best_value = 0
        for key in sorted(groups):
            members = groups[key]
            matched, observed, detail = self._evaluate_group(members)
            label = "|".join(key) if key else "(all events)"
            explanation.append(f"group {label}: {detail}")
            best_value = max(best_value, observed)
            if matched:
                return CorrelationResult(
                    matched=True,
                    correlation_type=str(self.definition.type),
                    groups_evaluated=len(groups),
                    events_considered=len(annotated),
                    events_skipped=skipped,
                    matching_group=label,
                    observed_value=observed,
                    explanation=tuple(explanation),
                )

        return CorrelationResult(
            matched=False,
            correlation_type=str(self.definition.type),
            groups_evaluated=len(groups),
            events_considered=len(annotated),
            events_skipped=skipped,
            matching_group=None,
            observed_value=best_value,
            explanation=tuple(explanation),
        )

    def _annotate(self, events: Sequence[SyntheticEvent]) -> tuple[list[_Annotated], int]:
        """Tag each event with the base rules it matches and its group key."""
        annotated: list[_Annotated] = []
        skipped = 0
        for event in events:
            matched_rules = frozenset(
                name for name in self.definition.rules if self.base_matchers[name].match(event)
            )
            if not matched_rules:
                continue
            group = self._group_key(event, matched_rules)
            if group is None:
                skipped += 1
                continue
            annotated.append(_Annotated(event=event, rules=matched_rules, group=group))
        annotated.sort(key=lambda item: (item.event.timestamp, item.event.event_id))
        return annotated, skipped

    def _group_key(
        self,
        event: SyntheticEvent,
        matched_rules: frozenset[str],
    ) -> tuple[str, ...] | None:
        """Return the group key, or ``None`` when a ``group-by`` field is absent."""
        if not self.definition.group_by:
            return ()
        values: list[str] = []
        for name in self.definition.group_by:
            field_name = self.definition.resolve_field(name, matched_rules)
            if field_name is None:
                return None
            value = event.lookup(field_name)
            if value is SENTINEL_MISSING or value is None:
                return None
            values.append(str(value).casefold())
        return tuple(values)

    @staticmethod
    def _group(annotated: Sequence[_Annotated]) -> dict[tuple[str, ...], list[_Annotated]]:
        groups: dict[tuple[str, ...], list[_Annotated]] = {}
        for item in annotated:
            groups.setdefault(item.group, []).append(item)
        return groups

    def _windows(self, members: Sequence[_Annotated]) -> list[list[_Annotated]]:
        """Return the sliding windows anchored on each member, inclusive of both ends."""
        span = timedelta(seconds=self.definition.timespan_seconds)
        windows: list[list[_Annotated]] = []
        for start in range(len(members)):
            anchor = members[start].event.timestamp
            window = [
                members[index]
                for index in range(start, len(members))
                if members[index].event.timestamp - anchor <= span
            ]
            windows.append(window)
        return windows

    def _evaluate_group(self, members: Sequence[_Annotated]) -> tuple[bool, int, str]:
        definition = self.definition
        best = 0
        for window in self._windows(members):
            if definition.type is CorrelationType.EVENT_COUNT:
                observed = len(window)
            elif definition.type is CorrelationType.VALUE_COUNT:
                observed = self._distinct_values(window)
            elif definition.type is CorrelationType.TEMPORAL:
                observed = len(self._rules_present(window))
            else:
                observed = self._ordered_prefix(window)

            best = max(best, observed)
            if self._satisfied(observed):
                return True, observed, self._detail(observed, satisfied=True)
        return False, best, self._detail(best, satisfied=False)

    def _distinct_values(self, window: Sequence[_Annotated]) -> int:
        field_name = self.definition.value_field or ""
        seen: set[str] = set()
        for item in window:
            value = item.event.lookup(field_name)
            if value is SENTINEL_MISSING or value is None:
                continue
            seen.add(str(value).casefold())
        return len(seen)

    def _rules_present(self, window: Sequence[_Annotated]) -> set[str]:
        present: set[str] = set()
        for item in window:
            present.update(item.rules)
        return present & set(self.definition.rules)

    def _ordered_prefix(self, window: Sequence[_Annotated]) -> int:
        """Return how many referenced rules appear, in order, as a subsequence."""
        expected = list(self.definition.rules)
        position = 0
        for item in window:
            if position < len(expected) and expected[position] in item.rules:
                position += 1
        return position

    def _satisfied(self, observed: int) -> bool:
        definition = self.definition
        if definition.type in (CorrelationType.EVENT_COUNT, CorrelationType.VALUE_COUNT):
            condition = definition.condition
            if condition is None:  # pragma: no cover - parser guarantees presence
                raise CorrelationError(f"{self.source}: counting correlation has no condition")
            return condition.evaluate(observed)
        return observed >= len(definition.rules)

    def _detail(self, observed: int, *, satisfied: bool) -> str:
        definition = self.definition
        verdict = "satisfied" if satisfied else "not satisfied"
        if definition.type is CorrelationType.EVENT_COUNT:
            target = definition.condition.render() if definition.condition else "?"
            return f"best event count {observed} vs {target} -> {verdict}"
        if definition.type is CorrelationType.VALUE_COUNT:
            target = definition.condition.render() if definition.condition else "?"
            return (
                f"best distinct '{definition.value_field}' count {observed} vs {target} "
                f"-> {verdict}"
            )
        if definition.type is CorrelationType.TEMPORAL:
            return (
                f"best {observed}/{len(definition.rules)} referenced rules present in window "
                f"-> {verdict}"
            )
        return (
            f"best ordered prefix {observed}/{len(definition.rules)} rules in sequence -> {verdict}"
        )


def synthetic_timeline(
    count: int,
    *,
    start: datetime | None = None,
    step_seconds: int = 30,
) -> list[datetime]:
    """Generate a deterministic ascending run of UTC timestamps for fixtures.

    The default epoch is fixed rather than ``now`` so generated fixtures are
    byte-identical between runs.
    """
    if count < 0:
        raise CorrelationError("synthetic_timeline: count must not be negative")
    origin = start or datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    if origin.tzinfo is None:
        origin = origin.replace(tzinfo=UTC)
    return [origin + timedelta(seconds=step_seconds * index) for index in range(count)]


__all__ = [
    "CONDITION_OPERATORS",
    "MAX_EVENTS",
    "MAX_TIMESPAN_SECONDS",
    "UNIT_SECONDS",
    "CorrelationDefinition",
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelationType",
    "CountCondition",
    "format_timespan",
    "parse_correlation",
    "parse_count_condition",
    "parse_timespan",
    "synthetic_timeline",
]
