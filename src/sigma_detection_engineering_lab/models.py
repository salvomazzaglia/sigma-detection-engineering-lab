"""Domain dataclasses shared across the laboratory.

Everything here is plain data with a ``to_dict`` method, so any subsystem can be
serialised into a report without the report modules needing to know how the data
was produced.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from sigma_detection_engineering_lab.event_model import SyntheticEvent, format_timestamp
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import Maturity, SigmaStatus


def normalise_date(value: object) -> str | None:
    """Render a YAML date, datetime, or string as ``YYYY-MM-DD``.

    Unquoted YAML dates arrive as :class:`datetime.date`, so rules are normalised
    once here instead of every consumer handling both shapes.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        return value.strip()
    return str(value)


class FindingCategory(str, Enum):
    """Which subsystem produced a finding."""

    STRUCTURE = "structure"
    CONVENTION = "convention"
    METADATA = "metadata"
    ATTACK = "attack"
    TELEMETRY = "telemetry"
    BEHAVIOR = "behavior"
    CORRELATION = "correlation"
    CONVERSION = "conversion"
    COVERAGE = "coverage"
    CATALOG = "catalog"
    FIXTURE = "fixture"
    SAFETY = "safety"

    def __str__(self) -> str:
        return self.value


class TestOutcome(str, Enum):
    """Result of one behavioral test case."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"

    def __str__(self) -> str:
        return self.value


class ConversionStatus(str, Enum):
    """Outcome of one backend conversion attempt.

    ``UNSUPPORTED`` and ``BACKEND_UNAVAILABLE`` are never counted as successes;
    quality gates treat them as distinct from ``CONVERTED`` on purpose.
    """

    CONVERTED = "converted"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return self.value


class FixtureKind(str, Enum):
    """Whether a fixture asserts a match or a rejection."""

    POSITIVE = "positive"
    NEGATIVE = "negative"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class LogSource:
    """Sigma ``logsource`` block."""

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None

    @property
    def is_empty(self) -> bool:
        """Return whether no selector component was specified."""
        return not any((self.category, self.product, self.service))

    @property
    def key(self) -> str:
        """Stable identifier used to group rules and coverage by logsource."""
        return "/".join(part or "*" for part in (self.product, self.category, self.service))

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in (
                ("category", self.category),
                ("product", self.product),
                ("service", self.service),
                ("definition", self.definition),
            )
            if value is not None
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> LogSource:
        if not data:
            return cls()
        return cls(
            category=_as_optional_str(data.get("category")),
            product=_as_optional_str(data.get("product")),
            service=_as_optional_str(data.get("service")),
            definition=_as_optional_str(data.get("definition")),
        )


def _as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


@dataclass(frozen=True)
class Rule:
    """A parsed Sigma rule together with its catalog identity.

    ``documents`` retains every YAML document from the source file so correlation
    rules keep their referenced base rules, and so conversion can re-serialise the
    original text rather than a lossy reconstruction.
    """

    catalog_id: str
    rule_id: str
    title: str
    path: Path
    relative_path: str
    description: str = ""
    status: SigmaStatus = SigmaStatus.EXPERIMENTAL
    level: Severity = Severity.MEDIUM
    author: str = ""
    license: str | None = None
    date: str | None = None
    modified: str | None = None
    name: str | None = None
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    logsource: LogSource = field(default_factory=LogSource)
    detection: Mapping[str, Any] = field(default_factory=dict)
    related: tuple[Mapping[str, Any], ...] = ()
    is_correlation: bool = False
    correlation: Mapping[str, Any] | None = None
    documents: tuple[Mapping[str, Any], ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)
    raw_text: str = ""

    @property
    def condition(self) -> Any:
        """Return the raw ``detection.condition`` value, if present."""
        return self.detection.get("condition") if self.detection else None

    @property
    def attack_tags(self) -> tuple[str, ...]:
        """Return only the ``attack.`` namespaced tags."""
        return tuple(tag for tag in self.tags if tag.lower().startswith("attack."))

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "path": self.relative_path,
            "description": self.description,
            "status": str(self.status),
            "level": str(self.level),
            "author": self.author,
            "license": self.license,
            "date": self.date,
            "modified": self.modified,
            "name": self.name,
            "references": list(self.references),
            "tags": list(self.tags),
            "falsepositives": list(self.falsepositives),
            "fields": list(self.fields),
            "logsource": self.logsource.to_dict(),
            "is_correlation": self.is_correlation,
            "correlation_type": (str(self.correlation.get("type")) if self.correlation else None),
        }


@dataclass(frozen=True)
class TelemetryRequirement:
    """One telemetry source a rule depends on, as declared in its sidecar."""

    telemetry_id: str
    description: str = ""
    required_fields: tuple[str, ...] = ()
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_id": self.telemetry_id,
            "description": self.description,
            "required_fields": list(self.required_fields),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class AttackMapping:
    """MITRE ATT&CK mapping declared by a sidecar.

    An empty mapping is legitimate when ``reason`` explains why the detection has
    no ATT&CK correspondence. Identifiers that are not present in the vendored
    catalog are always a failure: inventing IDs is worse than declaring none.
    """

    techniques: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    detection_strategies: tuple[str, ...] = ()
    analytics: tuple[str, ...] = ()
    data_components: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.techniques,
                self.tactics,
                self.detection_strategies,
                self.analytics,
                self.data_components,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": list(self.techniques),
            "tactics": list(self.tactics),
            "detection_strategies": list(self.detection_strategies),
            "analytics": list(self.analytics),
            "data_components": list(self.data_components),
            "reason": self.reason,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> AttackMapping:
        if not data:
            return cls()
        return cls(
            techniques=_identifier_tuple(data.get("techniques")),
            tactics=_identifier_tuple(data.get("tactics")),
            detection_strategies=_identifier_tuple(data.get("detection_strategies")),
            analytics=_identifier_tuple(data.get("analytics")),
            data_components=_identifier_tuple(data.get("data_components")),
            reason=_as_optional_str(data.get("reason")),
        )

    @classmethod
    def from_sidecar(cls, data: Mapping[str, Any] | None) -> AttackMapping:
        """Build a mapping from the ``attack_*`` keys of a sidecar document.

        Sidecars record each object as ``{"id": ..., "name": ...}`` so a reader can
        see what an identifier refers to without consulting the catalog. Only the
        identifier is authoritative here; the name is documentation.
        """
        if not data:
            return cls()
        return cls(
            techniques=_identifier_tuple(data.get("attack_techniques")),
            tactics=_identifier_tuple(data.get("attack_tactics")),
            detection_strategies=_identifier_tuple(data.get("attack_detection_strategies")),
            analytics=_identifier_tuple(data.get("attack_analytics")),
            data_components=_identifier_tuple(data.get("attack_data_components")),
            reason=_as_optional_str(data.get("unmapped_defensive_objects_reason")),
        )


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    return (str(value),)


def _identifier_tuple(value: object) -> tuple[str, ...]:
    """Extract identifiers from a list of strings or of ``{"id": ...}`` objects."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),)
    if isinstance(value, Mapping):
        identifier = value.get("id")
        return (str(identifier).strip(),) if identifier else ()
    if isinstance(value, Sequence):
        result: list[str] = []
        for item in value:
            if isinstance(item, Mapping):
                identifier = item.get("id")
                if identifier:
                    result.append(str(identifier).strip())
            elif item is not None:
                text = str(item).strip()
                if text:
                    result.append(text)
        return tuple(result)
    return (str(value).strip(),)


@dataclass(frozen=True)
class SidecarMetadata:
    """Laboratory metadata stored alongside a rule.

    The sidecar holds everything the Sigma specification has no field for:
    the hypothesis behind the detection, what telemetry it needs, how mature the
    evidence is, and what the rule knowingly does not cover.
    """

    catalog_id: str
    rule_id: str
    maturity: Maturity
    path: Path
    relative_path: str
    title: str = ""
    detection_hypothesis: str = ""
    telemetry_requirements: tuple[TelemetryRequirement, ...] = ()
    attack_mapping: AttackMapping = field(default_factory=AttackMapping)
    validation_notes: str = ""
    known_limitations: tuple[str, ...] = ()
    tuning_guidance: tuple[str, ...] = ()
    synthetic_only: bool = True
    platform: str | None = None
    rule_family: str | None = None
    required_logs: tuple[str, ...] = ()
    required_channels: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    optional_fields: tuple[str, ...] = ()
    supported_backends: tuple[str, ...] = ()
    unsupported_backend_reasons: Mapping[str, str] = field(default_factory=dict)
    related_rules: tuple[str, ...] = ()
    minimum_positive_tests: int = 0
    minimum_negative_tests: int = 0
    author: str = ""
    license: str | None = None
    attack_version: str | None = None
    rule_file: str | None = None
    fixture_directory: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def declared_fields(self) -> tuple[str, ...]:
        """Every field the sidecar claims its telemetry provides."""
        seen: dict[str, None] = {}
        for name in (*self.required_fields, *self.optional_fields):
            seen.setdefault(name, None)
        for requirement in self.telemetry_requirements:
            for name in requirement.required_fields:
                seen.setdefault(name, None)
        return tuple(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "maturity": str(self.maturity),
            "path": self.relative_path,
            "detection_hypothesis": self.detection_hypothesis,
            "telemetry_requirements": [item.to_dict() for item in self.telemetry_requirements],
            "attack_mapping": self.attack_mapping.to_dict(),
            "validation_notes": self.validation_notes,
            "known_limitations": list(self.known_limitations),
            "tuning_guidance": list(self.tuning_guidance),
            "synthetic_only": self.synthetic_only,
            "platform": self.platform,
            "rule_family": self.rule_family,
            "required_logs": list(self.required_logs),
            "required_channels": list(self.required_channels),
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "supported_backends": list(self.supported_backends),
            "unsupported_backend_reasons": dict(self.unsupported_backend_reasons),
            "related_rules": list(self.related_rules),
            "minimum_positive_tests": self.minimum_positive_tests,
            "minimum_negative_tests": self.minimum_negative_tests,
            "rule_file": self.rule_file,
            "fixture_directory": self.fixture_directory,
        }


@dataclass(frozen=True)
class FixtureCase:
    """One event paired with the outcome the rule is expected to produce."""

    case_id: str
    catalog_id: str
    kind: FixtureKind
    event: SyntheticEvent
    description: str = ""
    source_path: str = ""

    @property
    def expects_match(self) -> bool:
        return self.kind is FixtureKind.POSITIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "catalog_id": self.catalog_id,
            "kind": str(self.kind),
            "description": self.description,
            "source_path": self.source_path,
            "event": self.event.to_mapping(),
        }


@dataclass(frozen=True)
class CorrelationSequence:
    """An ordered run of events used to exercise a correlation rule."""

    sequence_id: str
    catalog_id: str
    kind: FixtureKind
    events: tuple[SyntheticEvent, ...]
    description: str = ""
    source_path: str = ""

    @property
    def expects_match(self) -> bool:
        return self.kind is FixtureKind.POSITIVE

    @property
    def span_seconds(self) -> float:
        """Return the wall-clock span of the sequence, or zero if under two events."""
        if len(self.events) < 2:
            return 0.0
        ordered = sorted(self.events, key=lambda item: item.timestamp)
        return (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "catalog_id": self.catalog_id,
            "kind": str(self.kind),
            "description": self.description,
            "source_path": self.source_path,
            "event_count": len(self.events),
            "span_seconds": self.span_seconds,
            "events": [event.to_mapping() for event in self.events],
        }


@dataclass(frozen=True)
class ValidationFinding:
    """A single validation observation.

    Findings are quality observations about detection content. They are not
    vulnerability reports, and the SARIF writer is careful to say so.
    """

    code: str
    category: FindingCategory
    severity: Severity
    message: str
    subject: str
    path: str | None = None
    line: int | None = None
    gate: str | None = None
    remediation: str | None = None

    @property
    def is_error(self) -> bool:
        """Return whether this finding should fail a run."""
        return self.severity.at_least(Severity.HIGH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": str(self.category),
            "severity": str(self.severity),
            "message": self.message,
            "subject": self.subject,
            "path": self.path,
            "line": self.line,
            "gate": self.gate,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ValidationReport:
    """All findings from one validation run, plus the rules that were examined."""

    findings: tuple[ValidationFinding, ...] = ()
    rules_examined: int = 0
    generated_at: str = ""

    @property
    def errors(self) -> tuple[ValidationFinding, ...]:
        return tuple(finding for finding in self.findings if finding.is_error)

    @property
    def warnings(self) -> tuple[ValidationFinding, ...]:
        return tuple(finding for finding in self.findings if not finding.is_error)

    @property
    def passed(self) -> bool:
        return not self.errors

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            key = str(finding.severity)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "rules_examined": self.rules_examined,
            "generated_at": self.generated_at,
            "counts_by_severity": self.counts_by_severity(),
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class TestResult:
    """Outcome of one fixture case or correlation sequence."""

    case_id: str
    catalog_id: str
    outcome: TestOutcome
    expected_match: bool
    actual_match: bool | None
    duration_seconds: float = 0.0
    message: str = ""
    kind: str = "event"
    explanation: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.outcome is TestOutcome.PASSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "catalog_id": self.catalog_id,
            "outcome": str(self.outcome),
            "expected_match": self.expected_match,
            "actual_match": self.actual_match,
            "duration_seconds": round(self.duration_seconds, 6),
            "message": self.message,
            "kind": self.kind,
            "explanation": list(self.explanation),
        }


@dataclass(frozen=True)
class TestSummary:
    """Aggregated behavioral test results for the whole catalog."""

    results: tuple[TestResult, ...] = ()
    generated_at: str = ""
    evaluator: str = ""

    @property
    def total(self) -> int:
        return len(self.results)

    def count(self, outcome: TestOutcome) -> int:
        return sum(1 for result in self.results if result.outcome is outcome)

    @property
    def passed(self) -> int:
        return self.count(TestOutcome.PASSED)

    @property
    def failed(self) -> int:
        return self.count(TestOutcome.FAILED)

    @property
    def errored(self) -> int:
        return self.count(TestOutcome.ERROR)

    @property
    def skipped(self) -> int:
        return self.count(TestOutcome.SKIPPED)

    @property
    def unsupported(self) -> int:
        return self.count(TestOutcome.UNSUPPORTED)

    @property
    def successful(self) -> bool:
        """Unsupported cases are not successes; they block just like failures."""
        return self.failed == 0 and self.errored == 0 and self.unsupported == 0

    def results_for(self, catalog_id: str) -> tuple[TestResult, ...]:
        return tuple(result for result in self.results if result.catalog_id == catalog_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "evaluator": self.evaluator,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "skipped": self.skipped,
            "unsupported": self.unsupported,
            "successful": self.successful,
            "results": [result.to_dict() for result in self.results],
        }


@dataclass(frozen=True)
class ConversionResult:
    """One rule converted, or not converted, by one backend."""

    catalog_id: str
    backend: str
    status: ConversionStatus
    queries: tuple[str, ...] = ()
    message: str = ""
    banner: str = ""
    backend_version: str | None = None
    dialect: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status is ConversionStatus.CONVERTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "backend": self.backend,
            "status": str(self.status),
            "queries": list(self.queries),
            "message": self.message,
            "banner": self.banner,
            "backend_version": self.backend_version,
            "dialect": self.dialect,
            "production_ready": False,
        }


@dataclass(frozen=True)
class GateResult:
    """Outcome of one configured quality gate."""

    gate: str
    passed: bool
    enabled: bool = True
    detail: str = ""
    findings: tuple[ValidationFinding, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "passed": self.passed,
            "enabled": self.enabled,
            "detail": self.detail,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class QualityReport:
    """Result of applying every configured quality gate."""

    gates: tuple[GateResult, ...] = ()
    generated_at: str = ""
    rules_examined: int = 0

    @property
    def passed(self) -> bool:
        return all(gate.passed for gate in self.gates if gate.enabled)

    @property
    def failed_gates(self) -> tuple[GateResult, ...]:
        return tuple(gate for gate in self.gates if gate.enabled and not gate.passed)

    def all_findings(self) -> tuple[ValidationFinding, ...]:
        collected: list[ValidationFinding] = []
        for gate in self.gates:
            collected.extend(gate.findings)
        return tuple(collected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "generated_at": self.generated_at,
            "rules_examined": self.rules_examined,
            "gate_count": len(self.gates),
            "failed_gate_count": len(self.failed_gates),
            "gates": [gate.to_dict() for gate in self.gates],
        }


@dataclass(frozen=True)
class CoverageReport:
    """Authoring and testing coverage across the catalog.

    Deliberately excludes precision, recall, and false-positive rate. Those
    require labelled production telemetry, which this project never touches.
    """

    total_rules: int = 0
    rules_with_sidecar: int = 0
    rules_with_attack_mapping: int = 0
    rules_with_fixtures: int = 0
    rules_fully_tested: int = 0
    technique_counts: Mapping[str, int] = field(default_factory=dict)
    tactic_counts: Mapping[str, int] = field(default_factory=dict)
    logsource_counts: Mapping[str, int] = field(default_factory=dict)
    level_counts: Mapping[str, int] = field(default_factory=dict)
    status_counts: Mapping[str, int] = field(default_factory=dict)
    maturity_counts: Mapping[str, int] = field(default_factory=dict)
    unmapped_rules: tuple[str, ...] = ()
    untested_rules: tuple[str, ...] = ()
    generated_at: str = ""

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0

    @property
    def sidecar_ratio(self) -> float:
        return self._ratio(self.rules_with_sidecar, self.total_rules)

    @property
    def attack_mapping_ratio(self) -> float:
        return self._ratio(self.rules_with_attack_mapping, self.total_rules)

    @property
    def fixture_ratio(self) -> float:
        return self._ratio(self.rules_with_fixtures, self.total_rules)

    @property
    def tested_ratio(self) -> float:
        return self._ratio(self.rules_fully_tested, self.total_rules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_rules": self.total_rules,
            "rules_with_sidecar": self.rules_with_sidecar,
            "rules_with_attack_mapping": self.rules_with_attack_mapping,
            "rules_with_fixtures": self.rules_with_fixtures,
            "rules_fully_tested": self.rules_fully_tested,
            "sidecar_ratio": self.sidecar_ratio,
            "attack_mapping_ratio": self.attack_mapping_ratio,
            "fixture_ratio": self.fixture_ratio,
            "tested_ratio": self.tested_ratio,
            "unique_techniques": len(self.technique_counts),
            "unique_tactics": len(self.tactic_counts),
            "technique_counts": dict(self.technique_counts),
            "tactic_counts": dict(self.tactic_counts),
            "logsource_counts": dict(self.logsource_counts),
            "level_counts": dict(self.level_counts),
            "status_counts": dict(self.status_counts),
            "maturity_counts": dict(self.maturity_counts),
            "unmapped_rules": list(self.unmapped_rules),
            "untested_rules": list(self.untested_rules),
        }


def utc_now_iso() -> str:
    """Return the current UTC time in the canonical report timestamp form."""

    return format_timestamp(datetime.now(tz=UTC))


__all__ = [
    "AttackMapping",
    "ConversionResult",
    "ConversionStatus",
    "CorrelationSequence",
    "CoverageReport",
    "FindingCategory",
    "FixtureCase",
    "FixtureKind",
    "GateResult",
    "LogSource",
    "QualityReport",
    "Rule",
    "SidecarMetadata",
    "SyntheticEvent",
    "TelemetryRequirement",
    "TestOutcome",
    "TestResult",
    "TestSummary",
    "ValidationFinding",
    "ValidationReport",
    "normalise_date",
    "utc_now_iso",
]
