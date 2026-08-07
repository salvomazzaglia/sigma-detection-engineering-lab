"""Deterministic Sigma detection matcher for synthetic events.

This is a laboratory evaluator, not a SIEM backend. Its semantics are fixed and
documented so behavioral test results are reproducible and mean exactly one thing.
Where the Sigma specification leaves room for backend interpretation, this module
picks an explicit answer:

* **Case.** Comparisons are case-insensitive by default. The ``cased`` modifier
  makes a comparison case-sensitive, including for ``re``.
* **Wildcards.** ``*`` and ``?`` in plain values are Sigma wildcards; ``\\*``,
  ``\\?``, and ``\\\\`` are the literal characters.
* **Lists.** A list of values is a disjunction unless ``all`` is present, which
  turns it into a conjunction.
* **Null.** A ``null`` expected value matches an absent field or a present field
  holding null. Absent and null are otherwise distinct (see ``exists``).
* **Multi-valued fields.** If an event field holds a list, the expression matches
  when any element matches.
* **Regex.** ``re`` performs an unanchored search, guarded by static length and
  complexity limits since Python's ``re`` has no execution timeout.

Modifiers outside the documented set are refused rather than ignored: silently
dropping ``base64offset`` would make a rule appear tested when it is not.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from sigma_detection_engineering_lab.condition_model import ConditionNode
from sigma_detection_engineering_lab.condition_parser import parse_condition
from sigma_detection_engineering_lab.config import DEFAULT_EVALUATOR_PROFILE, EvaluatorProfile
from sigma_detection_engineering_lab.errors import (
    MatcherError,
    RegexSafetyError,
    UnsupportedModifierError,
)
from sigma_detection_engineering_lab.event_model import (
    SENTINEL_MISSING,
    SyntheticEvent,
    matches_logsource,
)

SUPPORTED_MODIFIERS: Final[frozenset[str]] = frozenset(
    {"contains", "startswith", "endswith", "re", "cidr", "exists", "all", "cased"}
)

COMPARISON_MODIFIERS: Final[frozenset[str]] = frozenset(
    {"contains", "startswith", "endswith", "re", "cidr", "exists"}
)
"""Modifiers that choose *how* to compare. At most one may appear per field."""

MAX_QUANTIFIERS: Final[int] = 24
MAX_REPEAT_BOUND: Final[int] = 1_000
MAX_REGEX_INPUT_LENGTH: Final[int] = 65_536

CONDITION_KEY: Final[str] = "condition"
TIMEFRAME_KEY: Final[str] = "timeframe"


@dataclass(frozen=True)
class MatchOptions:
    """Tunable, documented matcher behaviour."""

    max_regex_length: int = 256
    reject_catastrophic_patterns: bool = True
    default_case_sensitive: bool = False
    supported_modifiers: frozenset[str] = SUPPORTED_MODIFIERS
    max_regex_input_length: int = MAX_REGEX_INPUT_LENGTH

    @classmethod
    def from_profile(cls, profile: EvaluatorProfile | None = None) -> MatchOptions:
        """Build options from a loaded evaluator profile."""
        resolved = profile or DEFAULT_EVALUATOR_PROFILE
        return cls(
            max_regex_length=resolved.max_regex_length,
            reject_catastrophic_patterns=resolved.reject_catastrophic_patterns,
            default_case_sensitive=resolved.default_case_sensitive,
            supported_modifiers=frozenset(resolved.supported_modifiers),
        )


DEFAULT_OPTIONS: Final[MatchOptions] = MatchOptions()


# --------------------------------------------------------------------------- #
# Regular expression safety
# --------------------------------------------------------------------------- #


def _skip_char_class(pattern: str, index: int) -> int:
    """Return the index just past the character class starting at ``index``."""
    length = len(pattern)
    index += 1
    if index < length and pattern[index] == "^":
        index += 1
    if index < length and pattern[index] == "]":
        index += 1
    while index < length and pattern[index] != "]":
        if pattern[index] == "\\":
            index += 1
        index += 1
    return index + 1


def _quantifier_positions(pattern: str) -> list[int]:
    """Return indices of quantifiers that are active regex syntax.

    Escaped characters and anything inside a character class are ignored, so a
    literal ``\\*`` or ``[*+]`` does not count towards the complexity budget.
    """
    positions: list[int] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_char_class(pattern, index)
            continue
        if char in "*+" or (char == "{" and _looks_like_repeat(pattern, index)):
            positions.append(index)
        index += 1
    return positions


_REPEAT = re.compile(r"\{(\d*)(?:,(\d*))?\}")


def _looks_like_repeat(pattern: str, index: int) -> bool:
    match = _REPEAT.match(pattern, index)
    return bool(match and (match.group(1) or match.group(2)))


def _repeat_bounds(pattern: str) -> list[int]:
    """Return every explicit repetition bound appearing in the pattern."""
    bounds: list[int] = []
    for match in _REPEAT.finditer(pattern):
        for group in match.groups():
            if group:
                bounds.append(int(group))
    return bounds


def _has_nested_quantifier(pattern: str) -> bool:
    """Detect a quantified group whose body is itself quantified.

    ``(a+)+`` and ``(a*)*`` are the classic catastrophic-backtracking shapes.
    Detection is structural and conservative: it can reject a pattern that would
    in practice be fine, which is the correct direction to err in.
    """
    stack: list[int] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_char_class(pattern, index)
            continue
        if char == "(":
            stack.append(index)
            index += 1
            continue
        if char == ")":
            if stack:
                start = stack.pop()
                body = pattern[start + 1 : index]
                following = pattern[index + 1 : index + 2]
                quantified_after = following in {"*", "+"} or (
                    following == "{" and _looks_like_repeat(pattern, index + 1)
                )
                if quantified_after and _quantifier_positions(body):
                    return True
            index += 1
            continue
        index += 1
    return False


_BACKREFERENCE = re.compile(r"(?<!\\)\\[1-9]")


def assert_safe_regex(
    pattern: str,
    *,
    max_length: int = 256,
    reject_catastrophic: bool = True,
    subject: str = "regex",
) -> None:
    """Reject regular expressions that are oversized or structurally dangerous.

    Python's :mod:`re` offers no execution timeout, so the guard has to be
    static: bound the pattern length, the number of quantifiers, repetition
    counts, nested quantifiers, and backreferences.

    Raises:
        RegexSafetyError: if any guard trips.
    """
    if len(pattern) > max_length:
        raise RegexSafetyError(
            f"{subject}: pattern length {len(pattern)} exceeds limit {max_length}"
        )
    if not reject_catastrophic:
        return

    quantifiers = _quantifier_positions(pattern)
    if len(quantifiers) > MAX_QUANTIFIERS:
        raise RegexSafetyError(
            f"{subject}: {len(quantifiers)} quantifiers exceed the complexity limit "
            f"of {MAX_QUANTIFIERS}"
        )
    for bound in _repeat_bounds(pattern):
        if bound > MAX_REPEAT_BOUND:
            raise RegexSafetyError(
                f"{subject}: repetition bound {{{bound}}} exceeds limit {MAX_REPEAT_BOUND}"
            )
    if _has_nested_quantifier(pattern):
        raise RegexSafetyError(
            f"{subject}: nested quantifier detected (a quantified group containing a "
            "quantifier); this shape can backtrack catastrophically"
        )
    if _BACKREFERENCE.search(pattern):
        raise RegexSafetyError(
            f"{subject}: backreferences are rejected because they can trigger "
            "exponential backtracking"
        )


def compile_regex(
    pattern: str,
    *,
    case_sensitive: bool,
    options: MatchOptions = DEFAULT_OPTIONS,
    subject: str = "regex",
) -> re.Pattern[str]:
    """Validate and compile a Sigma ``re`` pattern.

    Raises:
        RegexSafetyError: if the pattern is unsafe or does not compile.
    """
    assert_safe_regex(
        pattern,
        max_length=options.max_regex_length,
        reject_catastrophic=options.reject_catastrophic_patterns,
        subject=subject,
    )
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise RegexSafetyError(f"{subject}: invalid regular expression {pattern!r}: {exc}") from exc


def sigma_wildcard_to_regex(value: str) -> str:
    """Translate Sigma wildcard syntax into an equivalent regex fragment.

    ``*`` becomes ``.*``, ``?`` becomes ``.``; ``\\*``, ``\\?``, and ``\\\\``
    become the literal characters. Everything else is escaped.
    """
    parts: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char == "\\":
            following = value[index + 1] if index + 1 < length else ""
            if following in {"*", "?", "\\"}:
                parts.append(re.escape(following))
                index += 2
                continue
            parts.append(re.escape("\\"))
            index += 1
            continue
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        index += 1
    return "".join(parts)


def _to_text(value: Any) -> str:
    """Render a value for string comparison, with stable booleans."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# --------------------------------------------------------------------------- #
# Compiled expressions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FieldExpression:
    """One compiled ``Field|modifiers: value`` entry."""

    field_name: str
    modifiers: tuple[str, ...]
    comparison: str
    all_mode: bool
    cased: bool
    allows_null: bool
    exists_expected: bool | None
    patterns: tuple[re.Pattern[str], ...]
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    literals: tuple[Any, ...]
    source: str

    def render(self) -> str:
        """Re-render the original key, for explanations."""
        suffix = "".join(f"|{modifier}" for modifier in self.modifiers)
        return f"{self.field_name}{suffix}"

    def evaluate(self, event: SyntheticEvent, options: MatchOptions) -> bool:
        """Return whether this expression holds for ``event``."""
        if self.comparison == "exists":
            return event.has_field(self.field_name) is bool(self.exists_expected)

        raw = event.lookup(self.field_name)
        if raw is SENTINEL_MISSING:
            return self.allows_null
        if raw is None:
            return self.allows_null

        candidates: Sequence[Any]
        candidates = list(raw) if isinstance(raw, (list, tuple)) else [raw]

        if self.comparison == "cidr":
            return self._evaluate_cidr(candidates)

        if not self.patterns and not self.literals:
            # Only null was expected, and the field is present and non-null.
            return False

        if self.all_mode:
            return all(
                any(self._match_one(candidate, index) for candidate in candidates)
                for index in range(len(self.patterns))
            )
        return any(
            self._match_one(candidate, index)
            for candidate in candidates
            for index in range(len(self.patterns))
        )

    def _match_one(self, candidate: Any, index: int) -> bool:
        literal = self.literals[index]
        numeric_literal = isinstance(literal, (int, float)) and not isinstance(literal, bool)
        numeric_candidate = isinstance(candidate, (int, float)) and not isinstance(candidate, bool)
        if self.comparison == "plain" and numeric_literal and numeric_candidate:
            return bool(candidate == literal)

        text = _to_text(candidate)
        if len(text) > MAX_REGEX_INPUT_LENGTH:
            raise MatcherError(
                f"{self.source}: field {self.field_name!r} value of length {len(text)} exceeds "
                f"the matcher input limit {MAX_REGEX_INPUT_LENGTH}"
            )
        return self.patterns[index].search(text) is not None

    def _evaluate_cidr(self, candidates: Sequence[Any]) -> bool:
        if self.all_mode:
            return all(
                any(_address_in(candidate, network) for candidate in candidates)
                for network in self.networks
            )
        return any(
            _address_in(candidate, network) for candidate in candidates for network in self.networks
        )


def _address_in(
    value: Any,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    try:
        address = ipaddress.ip_address(_to_text(value).strip())
    except ValueError:
        return False
    return address in network


@dataclass(frozen=True)
class KeywordExpression:
    """A bare string in a selection list: an unfielded substring search."""

    pattern: re.Pattern[str]
    text: str

    def evaluate(self, event: SyntheticEvent, options: MatchOptions) -> bool:
        for value in event.fields.values():
            values = value if isinstance(value, (list, tuple)) else [value]
            for item in values:
                if item is None:
                    continue
                if self.pattern.search(_to_text(item)):
                    return True
        for attribute in (event.host, event.user, event.event_code):
            if attribute and self.pattern.search(_to_text(attribute)):
                return True
        return False

    def render(self) -> str:
        return f"keyword({self.text!r})"


@dataclass(frozen=True)
class SelectionBranch:
    """One alternative within a selection; all its expressions must hold."""

    expressions: tuple[FieldExpression, ...] = ()
    keywords: tuple[KeywordExpression, ...] = ()

    def evaluate(self, event: SyntheticEvent, options: MatchOptions) -> bool:
        return all(expression.evaluate(event, options) for expression in self.expressions) and all(
            keyword.evaluate(event, options) for keyword in self.keywords
        )


@dataclass(frozen=True)
class CompiledSelection:
    """A named detection selection: a disjunction over its branches."""

    name: str
    branches: tuple[SelectionBranch, ...]

    def evaluate(self, event: SyntheticEvent, options: MatchOptions) -> bool:
        return any(branch.evaluate(event, options) for branch in self.branches)


def _split_field_key(key: str, source: str) -> tuple[str, tuple[str, ...]]:
    parts = key.split("|")
    name = parts[0].strip()
    if not name:
        raise MatcherError(f"{source}: empty field name in key {key!r}")
    modifiers = tuple(part.strip().lower() for part in parts[1:] if part.strip())
    return name, modifiers


def _compile_field(
    key: str,
    value: Any,
    *,
    options: MatchOptions,
    source: str,
) -> FieldExpression:
    """Compile one ``Field|modifiers: value`` entry into an evaluable expression."""
    name, modifiers = _split_field_key(key, source)

    unknown = [modifier for modifier in modifiers if modifier not in options.supported_modifiers]
    if unknown:
        raise UnsupportedModifierError(
            f"{source}: field {key!r} uses unsupported modifier(s) {', '.join(unknown)}; "
            f"the lab evaluator supports: {', '.join(sorted(options.supported_modifiers))}"
        )

    comparisons = [modifier for modifier in modifiers if modifier in COMPARISON_MODIFIERS]
    if len(comparisons) > 1:
        raise UnsupportedModifierError(
            f"{source}: field {key!r} combines mutually exclusive modifiers "
            f"{', '.join(comparisons)}"
        )
    comparison = comparisons[0] if comparisons else "plain"
    all_mode = "all" in modifiers
    cased = "cased" in modifiers
    case_sensitive = cased or options.default_case_sensitive

    if comparison == "exists":
        if not isinstance(value, bool):
            raise MatcherError(
                f"{source}: field {key!r} with the 'exists' modifier requires a boolean, "
                f"got {type(value).__name__}"
            )
        return FieldExpression(
            field_name=name,
            modifiers=modifiers,
            comparison="exists",
            all_mode=False,
            cased=cased,
            allows_null=False,
            exists_expected=value,
            patterns=(),
            networks=(),
            literals=(),
            source=source,
        )

    raw_values: list[Any]
    if value is None:
        raw_values = []
    elif isinstance(value, (list, tuple)):
        raw_values = list(value)
    else:
        raw_values = [value]

    allows_null = value is None or any(item is None for item in raw_values)
    concrete = [item for item in raw_values if item is not None]

    if comparison == "cidr":
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for item in concrete:
            try:
                networks.append(ipaddress.ip_network(_to_text(item).strip(), strict=False))
            except ValueError as exc:
                raise MatcherError(
                    f"{source}: field {key!r} has an invalid CIDR value {item!r}: {exc}"
                ) from exc
        if not networks and not allows_null:
            raise MatcherError(f"{source}: field {key!r} with 'cidr' requires at least one network")
        return FieldExpression(
            field_name=name,
            modifiers=modifiers,
            comparison="cidr",
            all_mode=all_mode,
            cased=cased,
            allows_null=allows_null,
            exists_expected=None,
            patterns=(),
            networks=tuple(networks),
            literals=tuple(concrete),
            source=source,
        )

    patterns: list[re.Pattern[str]] = []
    for item in concrete:
        text = _to_text(item)
        if comparison == "re":
            patterns.append(
                compile_regex(
                    text,
                    case_sensitive=case_sensitive,
                    options=options,
                    subject=f"{source}: field {key!r}",
                )
            )
            continue

        body = sigma_wildcard_to_regex(text)
        # \A and \Z rather than ^ and $: a trailing newline in a field value must
        # not make an "endswith" or exact comparison succeed.
        if comparison == "contains":
            expression = rf"\A.*{body}.*\Z"
        elif comparison == "startswith":
            expression = rf"\A{body}.*\Z"
        elif comparison == "endswith":
            expression = rf"\A.*{body}\Z"
        else:
            expression = rf"\A{body}\Z"

        assert_safe_regex(
            expression,
            max_length=max(options.max_regex_length, len(expression)),
            reject_catastrophic=False,
            subject=f"{source}: field {key!r}",
        )
        flags = re.DOTALL if case_sensitive else re.IGNORECASE | re.DOTALL
        try:
            patterns.append(re.compile(expression, flags))
        except re.error as exc:  # pragma: no cover - escaping makes this unreachable
            raise MatcherError(
                f"{source}: field {key!r} produced an invalid pattern: {exc}"
            ) from exc

    return FieldExpression(
        field_name=name,
        modifiers=modifiers,
        comparison=comparison,
        all_mode=all_mode,
        cased=cased,
        allows_null=allows_null,
        exists_expected=None,
        patterns=tuple(patterns),
        networks=(),
        literals=tuple(concrete),
        source=source,
    )


def _compile_keyword(value: Any, *, options: MatchOptions, source: str) -> KeywordExpression:
    text = _to_text(value)
    body = sigma_wildcard_to_regex(text)
    flags = re.DOTALL if options.default_case_sensitive else re.IGNORECASE | re.DOTALL
    return KeywordExpression(pattern=re.compile(f".*{body}.*", flags), text=text)


def _compile_branch(
    entry: Any,
    *,
    options: MatchOptions,
    source: str,
) -> SelectionBranch:
    if isinstance(entry, Mapping):
        expressions = tuple(
            _compile_field(str(key), value, options=options, source=source)
            for key, value in entry.items()
        )
        return SelectionBranch(expressions=expressions)
    if isinstance(entry, (str, int, float, bool)):
        return SelectionBranch(keywords=(_compile_keyword(entry, options=options, source=source),))
    raise MatcherError(
        f"{source}: selection entry must be a mapping or a keyword scalar, "
        f"got {type(entry).__name__}"
    )


def compile_selection(
    name: str,
    definition: Any,
    *,
    options: MatchOptions = DEFAULT_OPTIONS,
    source: str = "detection",
) -> CompiledSelection:
    """Compile one named selection into an evaluable form.

    Raises:
        MatcherError: if the selection is structurally invalid.
        UnsupportedModifierError: if a field uses a modifier outside the subset.
    """
    label = f"{source}.{name}"
    branches: tuple[SelectionBranch, ...]
    if isinstance(definition, Mapping):
        branches = (_compile_branch(definition, options=options, source=label),)
    elif isinstance(definition, (list, tuple)):
        if not definition:
            raise MatcherError(f"{label}: selection list must not be empty")
        branches = tuple(
            _compile_branch(entry, options=options, source=f"{label}[{index}]")
            for index, entry in enumerate(definition)
        )
    else:
        raise MatcherError(
            f"{label}: selection must be a mapping or a list, got {type(definition).__name__}"
        )
    return CompiledSelection(name=name, branches=branches)


@dataclass(frozen=True)
class MatchResult:
    """Outcome of evaluating a detection against one event, with a rationale."""

    matched: bool
    condition: str
    selection_results: Mapping[str, bool] = field(default_factory=dict)
    explanation: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "condition": self.condition,
            "selection_results": dict(self.selection_results),
            "explanation": list(self.explanation),
        }


class DetectionMatcher:
    """Compiled Sigma ``detection`` block, evaluable against synthetic events."""

    def __init__(
        self,
        detection: Mapping[str, Any],
        *,
        options: MatchOptions = DEFAULT_OPTIONS,
        source: str = "detection",
    ) -> None:
        if not isinstance(detection, Mapping):
            raise MatcherError(f"{source}: detection must be a mapping")
        if CONDITION_KEY not in detection:
            raise MatcherError(f"{source}: detection is missing 'condition'")

        self.options = options
        self.source = source

        if TIMEFRAME_KEY in detection:
            raise MatcherError(
                f"{source}: 'timeframe' requires aggregation support, which is outside the "
                "lab subset; express time windows with a correlation rule instead"
            )

        self.selections: dict[str, CompiledSelection] = {}
        for key, value in detection.items():
            if key == CONDITION_KEY:
                continue
            self.selections[str(key)] = compile_selection(
                str(key), value, options=options, source=source
            )
        if not self.selections:
            raise MatcherError(f"{source}: detection defines no selections")

        self.condition: ConditionNode = parse_condition(
            detection[CONDITION_KEY], source=f"{source}.condition"
        )
        self.selection_names: tuple[str, ...] = tuple(self.selections)

        unknown = [
            name
            for name in self.condition.referenced_selections(self.selection_names)
            if name not in self.selections
        ]
        if unknown:
            raise MatcherError(
                f"{source}.condition references undefined selection(s): {', '.join(unknown)}"
            )

    def match(self, event: SyntheticEvent) -> bool:
        """Return whether the detection matches ``event``."""
        return self.evaluate(event).matched

    def evaluate(self, event: SyntheticEvent) -> MatchResult:
        """Evaluate the detection and return the result with per-selection detail.

        Selections are memoised per call so a selection referenced twice in the
        condition is evaluated once.
        """
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            if name not in cache:
                selection = self.selections.get(name)
                if selection is None:
                    raise MatcherError(
                        f"{self.source}.condition references undefined selection {name!r}"
                    )
                cache[name] = selection.evaluate(event, self.options)
            return cache[name]

        matched = self.condition.evaluate(resolve, self.selection_names)
        explanation = [
            f"selection {name}: {'match' if result else 'no match'}"
            for name, result in sorted(cache.items())
        ]
        explanation.append(f"condition {self.condition.render()} -> {matched}")
        return MatchResult(
            matched=matched,
            condition=self.condition.render(),
            selection_results=dict(cache),
            explanation=tuple(explanation),
        )

    def describe(self) -> list[str]:
        """Return a human-readable summary used by the ``explain`` command."""
        lines = [f"condition: {self.condition.render()}"]
        for name in self.selection_names:
            selection = self.selections[name]
            for index, branch in enumerate(selection.branches):
                prefix = f"  {name}" if len(selection.branches) == 1 else f"  {name}[{index}]"
                for expression in branch.expressions:
                    values = ", ".join(repr(item) for item in expression.literals) or "null"
                    lines.append(f"{prefix}: {expression.render()} -> {values}")
                for keyword in branch.keywords:
                    lines.append(f"{prefix}: {keyword.render()}")
        return lines


class RuleMatcher:
    """A detection matcher bound to a rule's logsource selector."""

    def __init__(
        self,
        detection: Mapping[str, Any],
        *,
        category: str | None = None,
        product: str | None = None,
        service: str | None = None,
        options: MatchOptions = DEFAULT_OPTIONS,
        source: str = "rule",
        enforce_logsource: bool = True,
    ) -> None:
        self.matcher = DetectionMatcher(detection, options=options, source=source)
        self.category = category
        self.product = product
        self.service = service
        self.enforce_logsource = enforce_logsource

    def logsource_matches(self, event: SyntheticEvent) -> bool:
        """Return whether the event's logsource satisfies the rule's selector."""
        if not self.enforce_logsource:
            return True
        return matches_logsource(event, self.category, self.product, self.service)

    def match(self, event: SyntheticEvent) -> bool:
        """Return whether logsource and detection both match."""
        return self.evaluate(event).matched

    def evaluate(self, event: SyntheticEvent) -> MatchResult:
        """Evaluate logsource then detection, short-circuiting on a logsource miss."""
        if not self.logsource_matches(event):
            return MatchResult(
                matched=False,
                condition=self.matcher.condition.render(),
                selection_results={},
                explanation=(
                    f"logsource mismatch: rule expects "
                    f"{self.product or '*'}/{self.category or '*'}/{self.service or '*'}, "
                    f"event is {event.logsource_label}",
                ),
            )
        return self.matcher.evaluate(event)


def build_rule_matcher(
    rule: Any,
    *,
    options: MatchOptions = DEFAULT_OPTIONS,
    enforce_logsource: bool = True,
) -> RuleMatcher:
    """Build a :class:`RuleMatcher` from a :class:`~models.Rule`.

    Accepts the rule structurally so this module stays independent of the rule
    loader's import graph.
    """
    logsource = rule.logsource
    return RuleMatcher(
        rule.detection,
        category=logsource.category,
        product=logsource.product,
        service=logsource.service,
        options=options,
        source=f"{rule.catalog_id}.detection",
        enforce_logsource=enforce_logsource,
    )


__all__ = [
    "COMPARISON_MODIFIERS",
    "DEFAULT_OPTIONS",
    "MAX_QUANTIFIERS",
    "MAX_REGEX_INPUT_LENGTH",
    "MAX_REPEAT_BOUND",
    "SUPPORTED_MODIFIERS",
    "CompiledSelection",
    "DetectionMatcher",
    "FieldExpression",
    "KeywordExpression",
    "MatchOptions",
    "MatchResult",
    "RuleMatcher",
    "SelectionBranch",
    "assert_safe_regex",
    "build_rule_matcher",
    "compile_regex",
    "compile_selection",
    "sigma_wildcard_to_regex",
]
