"""Coverage metrics over authored content.

What is measured here is how completely the catalog documents and tests itself:
how many rules have sidecars, ATT&CK mappings, and fixtures, and how many pass
their own behavioral tests.

What is deliberately **not** measured is detection efficacy. Precision, recall,
and false-positive rate all require labelled production telemetry. Computing them
from fixtures the rule author also wrote would measure nothing but the author's
self-consistency, while looking authoritative. Every report carries
:data:`~constants.COVERAGE_CAVEAT_BANNER` for the same reason.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sigma_detection_engineering_lab.attack_catalog import AttackCatalog
from sigma_detection_engineering_lab.constants import (
    COVERAGE_CAVEAT_BANNER,
    NO_EFFICACY_METRICS_NOTE,
)
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    CoverageReport,
    FixtureKind,
    Rule,
    TestOutcome,
    TestSummary,
    utc_now_iso,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog

EXCLUDED_METRICS: tuple[str, ...] = ("precision", "recall", "false_positive_rate", "accuracy")
"""Named so their absence is visibly intentional rather than an oversight."""


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def rule_is_fully_tested(catalog_id: str, summary: TestSummary | None) -> bool:
    """Return whether a rule has behavioral results and all of them passed.

    A rule with no results, or with any skipped, unsupported, failed, or errored
    result, is not fully tested.
    """
    if summary is None:
        return False
    results = summary.results_for(catalog_id)
    if not results:
        return False
    return all(result.outcome is TestOutcome.PASSED for result in results)


def rule_has_fixtures(catalog_id: str, fixtures: FixtureSet) -> bool:
    """Return whether any fixture is registered for a rule."""
    return bool(fixtures.cases_for(catalog_id) or fixtures.sequences_for(catalog_id))


def build_coverage(
    catalog: RuleCatalog,
    metadata: MetadataSet,
    fixtures: FixtureSet,
    summary: TestSummary | None = None,
) -> CoverageReport:
    """Compute the coverage report from loaded catalog content."""
    indexed = metadata.by_catalog_id()

    technique_counts: dict[str, int] = {}
    tactic_counts: dict[str, int] = {}
    logsource_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    maturity_counts: dict[str, int] = {}

    with_sidecar = 0
    with_mapping = 0
    with_fixtures = 0
    fully_tested = 0
    unmapped: list[str] = []
    untested: list[str] = []

    for rule in catalog:
        _increment(logsource_counts, rule.logsource.key)
        _increment(level_counts, str(rule.level))
        _increment(status_counts, str(rule.status))

        sidecar = indexed.get(rule.catalog_id)
        if sidecar is not None:
            with_sidecar += 1
            _increment(maturity_counts, str(sidecar.maturity))
            mapping = sidecar.attack_mapping
            if not mapping.is_empty:
                with_mapping += 1
                for technique in mapping.techniques:
                    _increment(technique_counts, technique.strip().upper())
                for tactic in mapping.tactics:
                    _increment(tactic_counts, tactic.strip().lower())
            else:
                unmapped.append(rule.catalog_id)
        else:
            unmapped.append(rule.catalog_id)

        if rule_has_fixtures(rule.catalog_id, fixtures):
            with_fixtures += 1
        if rule_is_fully_tested(rule.catalog_id, summary):
            fully_tested += 1
        else:
            untested.append(rule.catalog_id)

    return CoverageReport(
        total_rules=len(catalog),
        rules_with_sidecar=with_sidecar,
        rules_with_attack_mapping=with_mapping,
        rules_with_fixtures=with_fixtures,
        rules_fully_tested=fully_tested,
        technique_counts=dict(sorted(technique_counts.items())),
        tactic_counts=dict(sorted(tactic_counts.items())),
        logsource_counts=dict(sorted(logsource_counts.items())),
        level_counts=dict(sorted(level_counts.items())),
        status_counts=dict(sorted(status_counts.items())),
        maturity_counts=dict(sorted(maturity_counts.items())),
        unmapped_rules=tuple(sorted(unmapped)),
        untested_rules=tuple(sorted(untested)),
        generated_at=utc_now_iso(),
    )


@dataclass(frozen=True)
class FixtureBalance:
    """Per-rule fixture counts, used by the minimum-fixture quality gates."""

    catalog_id: str
    is_correlation: bool
    positive_events: int
    negative_events: int
    positive_sequences: int
    negative_sequences: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "is_correlation": self.is_correlation,
            "positive_events": self.positive_events,
            "negative_events": self.negative_events,
            "positive_sequences": self.positive_sequences,
            "negative_sequences": self.negative_sequences,
        }


def fixture_balance(catalog: RuleCatalog, fixtures: FixtureSet) -> tuple[FixtureBalance, ...]:
    """Return fixture counts for every rule in the catalog."""
    return tuple(
        FixtureBalance(
            catalog_id=rule.catalog_id,
            is_correlation=rule.is_correlation,
            positive_events=len(fixtures.cases_for(rule.catalog_id, FixtureKind.POSITIVE)),
            negative_events=len(fixtures.cases_for(rule.catalog_id, FixtureKind.NEGATIVE)),
            positive_sequences=len(fixtures.sequences_for(rule.catalog_id, FixtureKind.POSITIVE)),
            negative_sequences=len(fixtures.sequences_for(rule.catalog_id, FixtureKind.NEGATIVE)),
        )
        for rule in catalog
    )


def technique_gaps(
    coverage: CoverageReport,
    attack: AttackCatalog,
    *,
    limit: int = 25,
) -> tuple[str, ...]:
    """Return catalog techniques with no rule mapped to them.

    Only meaningful when the vendored ATT&CK subset is itself scoped to the
    techniques this project intends to address; against the full enterprise
    matrix the list is neither actionable nor a measure of anything.
    """
    if not attack.is_available:
        return ()
    mapped = {key.upper() for key in coverage.technique_counts}
    gaps = [
        technique_id
        for technique_id, obj in sorted(attack.techniques.items())
        if obj.is_active and technique_id.upper() not in mapped
    ]
    return tuple(gaps[:limit])


def coverage_payload(
    coverage: CoverageReport,
    *,
    attack: AttackCatalog | None = None,
    balances: Sequence[FixtureBalance] = (),
) -> dict[str, Any]:
    """Assemble the serialisable coverage document, banners included."""
    payload: dict[str, Any] = {
        "banner": COVERAGE_CAVEAT_BANNER,
        "excluded_metrics": list(EXCLUDED_METRICS),
        "excluded_metrics_note": NO_EFFICACY_METRICS_NOTE,
        **coverage.to_dict(),
    }
    if attack is not None:
        payload["attack_version"] = attack.attack_version
        payload["attack_catalog_available"] = attack.is_available
        payload["unmapped_catalog_techniques"] = list(technique_gaps(coverage, attack))
    if balances:
        payload["fixture_balance"] = [balance.to_dict() for balance in balances]
    return payload


def summarise_rules(rules: Sequence[Rule]) -> dict[str, Any]:
    """Summarise a rule selection for console output."""
    return {
        "count": len(rules),
        "correlation": sum(1 for rule in rules if rule.is_correlation),
        "levels": {
            level: sum(1 for rule in rules if str(rule.level) == level)
            for level in sorted({str(rule.level) for rule in rules})
        },
    }


__all__ = [
    "EXCLUDED_METRICS",
    "FixtureBalance",
    "build_coverage",
    "coverage_payload",
    "fixture_balance",
    "rule_has_fixtures",
    "rule_is_fully_tested",
    "summarise_rules",
    "technique_gaps",
]
