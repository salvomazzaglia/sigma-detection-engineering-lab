"""The in-memory rule catalog: identity, uniqueness, lookup, and filtering.

Two identifiers exist per rule and both must be unique across the catalog. The
``catalog_id`` is the filename stem, which humans use and CLI commands accept.
The ``rule_id`` is the Sigma UUID, which downstream tooling and ATT&CK Navigator
layers use. A collision in either is a hard error: two rules sharing an identity
make every report ambiguous.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from sigma_detection_engineering_lab.models import (
    FindingCategory,
    Rule,
    ValidationFinding,
)
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import SigmaStatus


@dataclass(frozen=True)
class RuleFilter:
    """Criteria for narrowing the catalog. Unset fields are ignored."""

    status: SigmaStatus | None = None
    level: Severity | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None
    technique: str | None = None
    tag: str | None = None
    correlation: bool | None = None
    text: str | None = None

    def matches(self, rule: Rule) -> bool:
        """Return whether ``rule`` satisfies every set criterion."""
        if self.status is not None and rule.status is not self.status:
            return False
        if self.level is not None and rule.level is not self.level:
            return False
        if self.correlation is not None and rule.is_correlation is not self.correlation:
            return False
        if not _matches_optional(self.product, rule.logsource.product):
            return False
        if not _matches_optional(self.category, rule.logsource.category):
            return False
        if not _matches_optional(self.service, rule.logsource.service):
            return False
        if self.technique is not None:
            wanted = f"attack.{self.technique.strip().lower()}"
            if not any(tag.lower() == wanted for tag in rule.tags):
                return False
        if self.tag is not None:
            wanted = self.tag.strip().lower()
            if not any(tag.lower() == wanted for tag in rule.tags):
                return False
        if self.text is not None:
            needle = self.text.strip().lower()
            haystack = " ".join(
                (rule.catalog_id, rule.title, rule.description, " ".join(rule.tags))
            ).lower()
            if needle not in haystack:
                return False
        return True


def _matches_optional(required: str | None, actual: str | None) -> bool:
    if required is None:
        return True
    if actual is None:
        return False
    return required.strip().lower() == actual.strip().lower()


class RuleCatalog:
    """An indexed, immutable view over a set of loaded rules."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: tuple[Rule, ...] = tuple(sorted(rules, key=lambda rule: rule.catalog_id))
        self._by_catalog_id: dict[str, Rule] = {}
        self._by_uuid: dict[str, Rule] = {}
        self._by_name: dict[str, Rule] = {}
        self._duplicate_catalog_ids: list[tuple[str, str, str]] = []
        self._duplicate_uuids: list[tuple[str, str, str]] = []

        for rule in self._rules:
            existing = self._by_catalog_id.get(rule.catalog_id)
            if existing is not None:
                self._duplicate_catalog_ids.append(
                    (rule.catalog_id, existing.relative_path, rule.relative_path)
                )
            else:
                self._by_catalog_id[rule.catalog_id] = rule

            if rule.rule_id:
                key = rule.rule_id.strip().lower()
                previous = self._by_uuid.get(key)
                if previous is not None:
                    self._duplicate_uuids.append(
                        (rule.rule_id, previous.relative_path, rule.relative_path)
                    )
                else:
                    self._by_uuid[key] = rule

            if rule.name:
                self._by_name.setdefault(rule.name.strip().lower(), rule)

            # Correlation files carry base rule documents whose 'name' fields are
            # referenced by correlation blocks in other files.
            for document in rule.documents:
                candidate = document.get("name")
                if isinstance(candidate, str) and candidate.strip():
                    self._by_name.setdefault(candidate.strip().lower(), rule)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules)

    def __contains__(self, catalog_id: object) -> bool:
        return isinstance(catalog_id, str) and catalog_id in self._by_catalog_id

    @property
    def rules(self) -> tuple[Rule, ...]:
        """Every rule, ordered by catalog identifier."""
        return self._rules

    @property
    def catalog_ids(self) -> tuple[str, ...]:
        return tuple(rule.catalog_id for rule in self._rules)

    def get(self, catalog_id: str) -> Rule | None:
        """Look up by catalog identifier."""
        return self._by_catalog_id.get(catalog_id)

    def by_uuid(self, rule_id: str) -> Rule | None:
        """Look up by Sigma UUID, case-insensitively."""
        return self._by_uuid.get(rule_id.strip().lower())

    def by_name(self, name: str) -> Rule | None:
        """Look up by Sigma ``name``, as referenced from correlation rules."""
        return self._by_name.get(name.strip().lower())

    def resolve(self, reference: str) -> Rule | None:
        """Resolve any identifier form: catalog id, UUID, or Sigma name."""
        needle = reference.strip()
        if not needle:
            return None
        return self.get(needle) or self.by_uuid(needle) or self.by_name(needle)

    def filter(self, criteria: RuleFilter | None = None, **kwargs: Any) -> tuple[Rule, ...]:
        """Return rules matching ``criteria``, or criteria built from keywords."""
        resolved = criteria if criteria is not None else RuleFilter(**kwargs)
        return tuple(rule for rule in self._rules if resolved.matches(rule))

    def standard_rules(self) -> tuple[Rule, ...]:
        """Return non-correlation rules."""
        return tuple(rule for rule in self._rules if not rule.is_correlation)

    def correlation_rules(self) -> tuple[Rule, ...]:
        """Return correlation rules."""
        return tuple(rule for rule in self._rules if rule.is_correlation)

    def group_by_logsource(self) -> dict[str, tuple[Rule, ...]]:
        """Group rules by their logsource key, for coverage summaries."""
        grouped: dict[str, list[Rule]] = {}
        for rule in self._rules:
            grouped.setdefault(rule.logsource.key, []).append(rule)
        return {key: tuple(value) for key, value in sorted(grouped.items())}

    def uniqueness_findings(self) -> tuple[ValidationFinding, ...]:
        """Return a finding for every duplicated catalog identifier or UUID."""
        findings: list[ValidationFinding] = []
        for catalog_id, first, second in self._duplicate_catalog_ids:
            findings.append(
                ValidationFinding(
                    code="SDEL-CAT-001",
                    category=FindingCategory.CATALOG,
                    severity=Severity.CRITICAL,
                    subject=catalog_id,
                    message=(
                        f"duplicate catalog identifier {catalog_id!r} used by {first} and {second}"
                    ),
                    path=second,
                    gate="unique_catalog_id",
                    remediation="Rename one of the files so every rule filename stem is unique.",
                )
            )
        for rule_id, first, second in self._duplicate_uuids:
            findings.append(
                ValidationFinding(
                    code="SDEL-CAT-002",
                    category=FindingCategory.CATALOG,
                    severity=Severity.CRITICAL,
                    subject=rule_id,
                    message=f"duplicate rule UUID {rule_id!r} used by {first} and {second}",
                    path=second,
                    gate="unique_uuid",
                    remediation="Generate a fresh UUIDv4 for one of the rules.",
                )
            )
        return tuple(findings)

    def summary(self) -> dict[str, Any]:
        """Return counts used by the console and JSON reports."""
        status_counts: dict[str, int] = {}
        level_counts: dict[str, int] = {}
        for rule in self._rules:
            status_counts[str(rule.status)] = status_counts.get(str(rule.status), 0) + 1
            level_counts[str(rule.level)] = level_counts.get(str(rule.level), 0) + 1
        return {
            "total": len(self._rules),
            "standard": len(self.standard_rules()),
            "correlation": len(self.correlation_rules()),
            "by_status": dict(sorted(status_counts.items())),
            "by_level": dict(sorted(level_counts.items())),
            "logsources": len(self.group_by_logsource()),
            "duplicate_catalog_ids": len(self._duplicate_catalog_ids),
            "duplicate_uuids": len(self._duplicate_uuids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "rules": [rule.to_dict() for rule in self._rules],
        }


def build_catalog(rules: Sequence[Rule]) -> RuleCatalog:
    """Convenience constructor mirroring the loader's return shape."""
    return RuleCatalog(rules)


__all__ = ["RuleCatalog", "RuleFilter", "build_catalog"]
