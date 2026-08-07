"""Comparing two saved reports to show what changed between runs.

Detection content drifts. A rule gets retired, a technique mapping is dropped, a
gate starts failing. Comparing a stored baseline report against the current one
turns that drift into an explicit list, which is what makes a coverage number
useful over time rather than a snapshot nobody revisits.

Direction is judged per metric, not globally: more rules mapped to ATT&CK is an
improvement, more untested rules is a regression, and metrics with no natural
direction are reported as neutral changes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.errors import PathSafetyError, ReportError
from sigma_detection_engineering_lab.models import utc_now_iso
from sigma_detection_engineering_lab.paths import DEFAULT_MAX_FILE_BYTES, safe_read_text

HIGHER_IS_BETTER: Final[frozenset[str]] = frozenset(
    {
        "total_rules",
        "rules_with_sidecar",
        "rules_with_attack_mapping",
        "rules_with_fixtures",
        "rules_fully_tested",
        "sidecar_ratio",
        "attack_mapping_ratio",
        "fixture_ratio",
        "tested_ratio",
        "unique_techniques",
        "unique_tactics",
        "passed",
    }
)

LOWER_IS_BETTER: Final[frozenset[str]] = frozenset(
    {
        "failed",
        "errored",
        "unsupported",
        "skipped",
        "error_count",
        "warning_count",
        "failed_gate_count",
    }
)

TRACKED_COVERAGE_KEYS: Final[tuple[str, ...]] = (
    "total_rules",
    "rules_with_sidecar",
    "rules_with_attack_mapping",
    "rules_with_fixtures",
    "rules_fully_tested",
    "sidecar_ratio",
    "attack_mapping_ratio",
    "fixture_ratio",
    "tested_ratio",
    "unique_techniques",
    "unique_tactics",
)


class Direction(str, Enum):
    """Whether a change is an improvement, a regression, or neither."""

    IMPROVED = "improved"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    NEUTRAL = "neutral"

    def __str__(self) -> str:
        return self.value


def classify(key: str, baseline: float, current: float) -> Direction:
    """Classify a numeric change for one metric."""
    if current == baseline:
        return Direction.UNCHANGED
    if key in HIGHER_IS_BETTER:
        return Direction.IMPROVED if current > baseline else Direction.REGRESSED
    if key in LOWER_IS_BETTER:
        return Direction.IMPROVED if current < baseline else Direction.REGRESSED
    return Direction.NEUTRAL


@dataclass(frozen=True)
class MetricChange:
    """One numeric metric compared across runs."""

    key: str
    baseline: float
    current: float
    direction: Direction

    @property
    def delta(self) -> float:
        return round(self.current - self.baseline, 6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "baseline": self.baseline,
            "current": self.current,
            "delta": self.delta,
            "direction": str(self.direction),
        }


@dataclass(frozen=True)
class SetChange:
    """Entries added to and removed from a named collection."""

    key: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "added": list(self.added),
            "removed": list(self.removed),
            "added_count": len(self.added),
            "removed_count": len(self.removed),
        }


@dataclass(frozen=True)
class ComparisonReport:
    """The full comparison between a baseline report and a current one."""

    metrics: tuple[MetricChange, ...] = ()
    sets: tuple[SetChange, ...] = ()
    gate_changes: tuple[tuple[str, str, str], ...] = ()
    baseline_label: str = "baseline"
    current_label: str = "current"
    generated_at: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def regressions(self) -> tuple[MetricChange, ...]:
        return tuple(change for change in self.metrics if change.direction is Direction.REGRESSED)

    @property
    def improvements(self) -> tuple[MetricChange, ...]:
        return tuple(change for change in self.metrics if change.direction is Direction.IMPROVED)

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions) or any(
            after == "failed" and before != "failed" for _, before, after in self.gate_changes
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "baseline": self.baseline_label,
            "current": self.current_label,
            "has_regressions": self.has_regressions,
            "improvement_count": len(self.improvements),
            "regression_count": len(self.regressions),
            "metrics": [change.to_dict() for change in self.metrics],
            "sets": [change.to_dict() for change in self.sets if change.changed],
            "gate_changes": [
                {"gate": gate, "baseline": before, "current": after}
                for gate, before, after in self.gate_changes
            ],
            "notes": list(self.notes),
        }


def load_report(path: Path, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> dict[str, Any]:
    """Read a JSON report produced by an earlier run.

    Raises:
        ReportError: if the file is unreadable or is not a JSON object.
    """
    try:
        text = safe_read_text(path, max_bytes=max_bytes)
    except PathSafetyError as exc:
        raise ReportError(f"{path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError(f"{path}: report root must be a JSON object")
    return data


def _find_section(report: Mapping[str, Any], *names: str) -> Mapping[str, Any]:
    """Locate a named section, tolerating both wrapped and bare report shapes."""
    for name in names:
        section = report.get(name)
        if isinstance(section, Mapping):
            return section
    return report


def _numeric(value: object) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return None


def compare_metrics(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    keys: Sequence[str],
) -> tuple[MetricChange, ...]:
    """Compare a fixed list of numeric keys across two documents."""
    changes: list[MetricChange] = []
    for key in keys:
        before = _numeric(baseline.get(key))
        after = _numeric(current.get(key))
        if before is None and after is None:
            continue
        before = before if before is not None else 0.0
        after = after if after is not None else 0.0
        changes.append(
            MetricChange(
                key=key,
                baseline=before,
                current=after,
                direction=classify(key, before, after),
            )
        )
    return tuple(changes)


def compare_counts(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    key: str,
) -> SetChange:
    """Compare the key sets of two count mappings, such as technique counts."""
    before = baseline.get(key)
    after = current.get(key)
    before_keys = set(before) if isinstance(before, Mapping) else set()
    after_keys = set(after) if isinstance(after, Mapping) else set()
    return SetChange(
        key=key,
        added=tuple(sorted(after_keys - before_keys)),
        removed=tuple(sorted(before_keys - after_keys)),
    )


def _as_set(value: object) -> set[Any]:
    """Coerce a report value to a set, treating anything unexpected as empty."""
    if isinstance(value, Sequence) and not isinstance(value, str):
        return set(value)
    return set()


def compare_lists(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    key: str,
) -> SetChange:
    """Compare two list-valued keys, such as untested rule identifiers."""
    before = baseline.get(key)
    after = current.get(key)
    before_set = _as_set(before)
    after_set = _as_set(after)
    return SetChange(
        key=key,
        added=tuple(sorted(str(item) for item in after_set - before_set)),
        removed=tuple(sorted(str(item) for item in before_set - after_set)),
    )


def compare_gates(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
) -> tuple[tuple[str, str, str], ...]:
    """Compare per-gate pass/fail state between two quality reports."""

    def index(document: Mapping[str, Any]) -> dict[str, str]:
        gates = document.get("gates")
        result: dict[str, str] = {}
        if isinstance(gates, Sequence) and not isinstance(gates, str):
            for entry in gates:
                if not isinstance(entry, Mapping):
                    continue
                name = entry.get("gate")
                if not isinstance(name, str):
                    continue
                if not entry.get("enabled", True):
                    result[name] = "disabled"
                else:
                    result[name] = "passed" if entry.get("passed") else "failed"
        return result

    before = index(baseline)
    after = index(current)
    changes: list[tuple[str, str, str]] = []
    for name in sorted(set(before) | set(after)):
        old = before.get(name, "absent")
        new = after.get(name, "absent")
        if old != new:
            changes.append((name, old, new))
    return tuple(changes)


def compare_reports(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    baseline_label: str = "baseline",
    current_label: str = "current",
) -> ComparisonReport:
    """Compare two report documents across coverage, testing, and quality gates.

    Both the wrapped report shape written by ``json_report`` and a bare coverage
    or quality document are accepted, so a saved section can be compared directly.
    """
    baseline_coverage = _find_section(baseline, "coverage")
    current_coverage = _find_section(current, "coverage")
    baseline_quality = _find_section(baseline, "quality")
    current_quality = _find_section(current, "quality")
    baseline_tests = _find_section(baseline, "tests", "testing")
    current_tests = _find_section(current, "tests", "testing")

    metrics: list[MetricChange] = []
    metrics.extend(compare_metrics(baseline_coverage, current_coverage, TRACKED_COVERAGE_KEYS))

    baseline_totals = _find_section(baseline_tests, "totals")
    current_totals = _find_section(current_tests, "totals")
    metrics.extend(
        compare_metrics(
            baseline_totals,
            current_totals,
            ("total", "passed", "failed", "errored", "skipped", "unsupported"),
        )
    )
    metrics.extend(
        compare_metrics(baseline_quality, current_quality, ("failed_gate_count", "gate_count"))
    )

    sets = [
        compare_counts(baseline_coverage, current_coverage, "technique_counts"),
        compare_counts(baseline_coverage, current_coverage, "tactic_counts"),
        compare_counts(baseline_coverage, current_coverage, "logsource_counts"),
        compare_lists(baseline_coverage, current_coverage, "untested_rules"),
        compare_lists(baseline_coverage, current_coverage, "unmapped_rules"),
    ]

    notes: list[str] = []
    if not any(key in baseline_coverage for key in TRACKED_COVERAGE_KEYS):
        notes.append("baseline document contains no recognised coverage section")
    if not any(key in current_coverage for key in TRACKED_COVERAGE_KEYS):
        notes.append("current document contains no recognised coverage section")

    return ComparisonReport(
        metrics=tuple(metrics),
        sets=tuple(sets),
        gate_changes=compare_gates(baseline_quality, current_quality),
        baseline_label=baseline_label,
        current_label=current_label,
        generated_at=utc_now_iso(),
        notes=tuple(notes),
    )


def compare_files(baseline_path: Path, current_path: Path) -> ComparisonReport:
    """Load two report files and compare them."""
    return compare_reports(
        load_report(baseline_path),
        load_report(current_path),
        baseline_label=baseline_path.name,
        current_label=current_path.name,
    )


__all__ = [
    "HIGHER_IS_BETTER",
    "LOWER_IS_BETTER",
    "TRACKED_COVERAGE_KEYS",
    "ComparisonReport",
    "Direction",
    "MetricChange",
    "SetChange",
    "classify",
    "compare_counts",
    "compare_files",
    "compare_gates",
    "compare_lists",
    "compare_metrics",
    "compare_reports",
    "load_report",
]
