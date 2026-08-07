"""Applying ``config/quality-gates.json`` to a completed analysis run.

A gate is a named, configurable pass/fail assertion. Most gates are satisfied by
the absence of findings tagged with that gate name, which keeps the gate list and
the validators loosely coupled: a validator emits a finding naming its gate, and
the gate fails if any such finding exists. The remainder are computed directly
from fixtures, test results, or conversion outcomes.

One rule governs the whole file: an outcome that could not be evaluated never
counts as a pass. A missing dependency, an absent ATT&CK catalog, or an
unsupported rule all fail their gate rather than passing by default. Gates are
worth having only if they cannot be satisfied by an incomplete run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig, read_config_json
from sigma_detection_engineering_lab.conversion import ConversionSet
from sigma_detection_engineering_lab.coverage import fixture_balance
from sigma_detection_engineering_lab.errors import ConfigError
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    ConversionStatus,
    FindingCategory,
    GateResult,
    QualityReport,
    TestOutcome,
    TestSummary,
    ValidationFinding,
    utc_now_iso,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

GATES_FILENAME: Final[str] = "quality-gates.json"

THRESHOLD_GATES: Final[tuple[str, ...]] = (
    "minimum_positive_fixtures_standard",
    "minimum_negative_fixtures_standard",
    "minimum_positive_sequences_correlation",
    "minimum_negative_sequences_correlation",
)

LIST_GATES: Final[tuple[str, ...]] = ("maturity_allowed",)

COMPUTED_GATES: Final[frozenset[str]] = frozenset(
    {
        "safe_yaml_load",
        "all_positive_must_match",
        "all_negative_must_reject",
        "conversion_status_recorded",
        "unsupported_not_counted_as_pass",
        *THRESHOLD_GATES,
        *LIST_GATES,
    }
)
"""Gates evaluated from data rather than from finding tags."""


@dataclass(frozen=True)
class QualityGateConfig:
    """Parsed ``quality-gates.json``."""

    gates: Mapping[str, Any] = field(default_factory=dict)
    falsepositive_banned_exact: tuple[str, ...] = ()
    notes: str = ""
    schema_version: str = ""
    source: str = GATES_FILENAME

    def is_enabled(self, name: str) -> bool:
        """Return whether a boolean gate is switched on."""
        value = self.gates.get(name)
        if isinstance(value, bool):
            return value
        return value is not None

    def threshold(self, name: str, default: int = 0) -> int:
        """Return an integer gate threshold."""
        value = self.gates.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            return default
        return value

    def allowed_list(self, name: str) -> tuple[str, ...]:
        """Return a list-valued gate's entries."""
        value = self.gates.get(name)
        if isinstance(value, Sequence) and not isinstance(value, str):
            return tuple(str(item) for item in value)
        return ()

    def boolean_gate_names(self) -> tuple[str, ...]:
        return tuple(name for name, value in self.gates.items() if isinstance(value, bool))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "gates": dict(self.gates),
            "falsepositive_banned_exact": list(self.falsepositive_banned_exact),
            "notes": self.notes,
        }


def load_quality_gates(config: LabConfig) -> QualityGateConfig:
    """Load ``config/quality-gates.json``.

    Raises:
        ConfigError: if the file is present but malformed. An absent file yields
            an empty configuration, which produces an empty report rather than a
            silent pass.
    """
    try:
        data = read_config_json(config, GATES_FILENAME)
    except ConfigError:
        return QualityGateConfig()

    gates = data.get("gates")
    if gates is None:
        return QualityGateConfig(schema_version=str(data.get("schema_version", "")))
    if not isinstance(gates, Mapping):
        raise ConfigError(f"{GATES_FILENAME}: 'gates' must be an object")

    banned = data.get("falsepositive_banned_exact", [])
    if isinstance(banned, str) or not isinstance(banned, Sequence):
        raise ConfigError(f"{GATES_FILENAME}: 'falsepositive_banned_exact' must be a list")

    return QualityGateConfig(
        gates=dict(gates),
        falsepositive_banned_exact=tuple(str(item) for item in banned),
        notes=str(data.get("notes", "")),
        schema_version=str(data.get("schema_version", "")),
    )


@dataclass(frozen=True)
class GateInputs:
    """Everything the gates need in order to reach a verdict."""

    config: LabConfig
    catalog: RuleCatalog
    metadata: MetadataSet
    fixtures: FixtureSet
    findings: tuple[ValidationFinding, ...] = ()
    test_summary: TestSummary | None = None
    conversions: ConversionSet | None = None
    load_failures: tuple[tuple[str, str], ...] = ()

    def findings_for_gate(self, gate: str) -> tuple[ValidationFinding, ...]:
        return tuple(finding for finding in self.findings if finding.gate == gate)


def _gate(
    name: str,
    passed: bool,
    detail: str,
    findings: Sequence[ValidationFinding] = (),
    *,
    enabled: bool = True,
) -> GateResult:
    return GateResult(
        gate=name,
        passed=passed,
        enabled=enabled,
        detail=detail,
        findings=tuple(findings),
    )


def _synthetic_finding(
    code: str,
    gate: str,
    subject: str,
    message: str,
    severity: Severity = Severity.HIGH,
    category: FindingCategory = FindingCategory.FIXTURE,
    path: str | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        category=category,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        gate=gate,
    )


def _evaluate_finding_gate(name: str, inputs: GateInputs) -> GateResult:
    """A tag-driven gate passes when no error-level finding names it."""
    tagged = inputs.findings_for_gate(name)
    blocking = tuple(finding for finding in tagged if finding.is_error)
    if blocking:
        return _gate(
            name,
            False,
            f"{len(blocking)} blocking finding(s) and {len(tagged) - len(blocking)} advisory",
            blocking,
        )
    if tagged:
        return _gate(name, True, f"{len(tagged)} advisory finding(s), none blocking", tagged)
    return _gate(name, True, "no findings")


def _evaluate_safe_yaml_load(inputs: GateInputs) -> GateResult:
    failures = inputs.load_failures
    if failures:
        findings = [
            _synthetic_finding(
                "SDEL-GATE-001",
                "safe_yaml_load",
                path,
                f"rule file could not be safely loaded: {message}",
                Severity.CRITICAL,
                FindingCategory.STRUCTURE,
                path,
            )
            for path, message in failures
        ]
        return _gate(
            "safe_yaml_load",
            False,
            f"{len(failures)} file(s) failed to load under the hardened YAML loader",
            findings,
        )
    if len(inputs.catalog) == 0:
        return _gate(
            "safe_yaml_load",
            False,
            "no rules were loaded, so the gate could not be demonstrated",
        )
    return _gate("safe_yaml_load", True, f"{len(inputs.catalog)} rule file(s) loaded safely")


def _evaluate_fixture_minimums(
    name: str,
    inputs: GateInputs,
    gate_config: QualityGateConfig,
) -> GateResult:
    threshold = gate_config.threshold(name)
    if threshold <= 0:
        return _gate(name, True, "threshold is zero, nothing to enforce")

    balances = fixture_balance(inputs.catalog, inputs.fixtures)
    correlation_gate = "correlation" in name
    attribute = {
        "minimum_positive_fixtures_standard": "positive_events",
        "minimum_negative_fixtures_standard": "negative_events",
        "minimum_positive_sequences_correlation": "positive_sequences",
        "minimum_negative_sequences_correlation": "negative_sequences",
    }[name]
    kind = "positive" if "positive" in name else "negative"
    unit = "sequence(s)" if correlation_gate else "event fixture(s)"

    findings: list[ValidationFinding] = []
    checked = 0
    for balance in balances:
        if balance.is_correlation != correlation_gate:
            continue
        checked += 1
        actual = getattr(balance, attribute)
        if actual < threshold:
            findings.append(
                _synthetic_finding(
                    "SDEL-GATE-010",
                    name,
                    balance.catalog_id,
                    f"has {actual} {kind} {unit} but the gate requires at least {threshold}",
                )
            )

    if findings:
        return _gate(
            name,
            False,
            f"{len(findings)} of {checked} rule(s) below the minimum of {threshold}",
            findings,
        )
    return _gate(name, True, f"all {checked} rule(s) meet the minimum of {threshold}")


def _evaluate_expectation_gate(name: str, inputs: GateInputs) -> GateResult:
    summary = inputs.test_summary
    if summary is None:
        return _gate(name, False, "behavioral tests were not run, so the gate is unproven")

    positive = name == "all_positive_must_match"
    relevant = [
        result
        for result in summary.results
        if result.expected_match is positive
        and result.outcome in (TestOutcome.PASSED, TestOutcome.FAILED, TestOutcome.ERROR)
    ]
    failures = [result for result in relevant if result.outcome is not TestOutcome.PASSED]

    if failures:
        findings = [
            _synthetic_finding(
                "SDEL-GATE-020",
                name,
                result.catalog_id,
                f"{result.case_id}: {result.message or result.outcome}",
                Severity.HIGH,
                FindingCategory.BEHAVIOR,
            )
            for result in failures
        ]
        return _gate(
            name,
            False,
            f"{len(failures)} of {len(relevant)} {'positive' if positive else 'negative'} "
            "case(s) did not behave as expected",
            findings,
        )
    if not relevant:
        return _gate(
            name,
            False,
            f"no {'positive' if positive else 'negative'} cases were executed",
        )
    return _gate(name, True, f"all {len(relevant)} case(s) behaved as expected")


def _evaluate_unsupported_not_counted(inputs: GateInputs) -> GateResult:
    name = "unsupported_not_counted_as_pass"
    summary = inputs.test_summary
    if summary is None:
        return _gate(name, False, "behavioral tests were not run, so the gate is unproven")

    unsupported = [
        result for result in summary.results if result.outcome is TestOutcome.UNSUPPORTED
    ]
    skipped = [result for result in summary.results if result.outcome is TestOutcome.SKIPPED]

    findings = [
        _synthetic_finding(
            "SDEL-GATE-030",
            name,
            result.catalog_id,
            f"{result.case_id}: {result.message or 'outside the documented evaluator subset'}",
            Severity.HIGH,
            FindingCategory.BEHAVIOR,
        )
        for result in unsupported
    ]
    findings.extend(
        _synthetic_finding(
            "SDEL-GATE-031",
            name,
            result.catalog_id,
            f"{result.case_id}: {result.message or 'no fixtures registered'}",
            Severity.MEDIUM,
            FindingCategory.BEHAVIOR,
        )
        for result in skipped
    )

    if unsupported or skipped:
        return _gate(
            name,
            False,
            f"{len(unsupported)} unsupported and {len(skipped)} skipped result(s) are "
            "reported as such and not as passes",
            findings,
        )
    return _gate(name, True, "every result was executed to a definite outcome")


def _evaluate_conversion_recorded(inputs: GateInputs) -> GateResult:
    name = "conversion_status_recorded"
    conversions = inputs.conversions
    if conversions is None:
        return _gate(name, False, "conversion was not attempted, so no status was recorded")

    if not conversions.results:
        return _gate(name, False, "no conversion results were recorded")

    missing_banner = [result for result in conversions.results if not result.banner.strip()]
    if missing_banner:
        findings = [
            _synthetic_finding(
                "SDEL-GATE-040",
                name,
                result.catalog_id,
                f"conversion for backend {result.backend} carries no demonstration banner",
                Severity.HIGH,
                FindingCategory.CONVERSION,
            )
            for result in missing_banner
        ]
        return _gate(name, False, f"{len(missing_banner)} result(s) lack the banner", findings)

    counts = conversions.counts()
    unavailable = counts.get(str(ConversionStatus.BACKEND_UNAVAILABLE), 0)
    detail = ", ".join(f"{status}={count}" for status, count in counts.items() if count)
    if unavailable and not conversions.any_backend_available:
        findings = [
            _synthetic_finding(
                "SDEL-GATE-041",
                name,
                handle.key,
                f"backend unavailable: {handle.error}",
                Severity.HIGH,
                FindingCategory.CONVERSION,
            )
            for handle in conversions.handles
            if not handle.available
        ]
        return _gate(
            name,
            False,
            f"no backend was available; statuses recorded but unproven ({detail})",
            findings,
        )
    return _gate(name, True, f"every attempt recorded a status ({detail})")


def _evaluate_maturity_allowed(inputs: GateInputs, gate_config: QualityGateConfig) -> GateResult:
    name = "maturity_allowed"
    allowed = {item.strip().lower() for item in gate_config.allowed_list(name)}
    if not allowed:
        return _gate(name, True, "no maturity restriction configured")

    findings = [
        _synthetic_finding(
            "SDEL-GATE-050",
            name,
            sidecar.catalog_id,
            f"maturity {sidecar.maturity} is outside the allowed set "
            f"({', '.join(sorted(allowed))})",
            Severity.HIGH,
            FindingCategory.METADATA,
            sidecar.relative_path,
        )
        for sidecar in inputs.metadata.sidecars
        if str(sidecar.maturity).lower() not in allowed
    ]
    if findings:
        return _gate(name, False, f"{len(findings)} sidecar(s) outside the allowed set", findings)
    return _gate(
        name,
        True,
        f"all {len(inputs.metadata.sidecars)} sidecar(s) within {', '.join(sorted(allowed))}",
    )


def apply_gates(
    inputs: GateInputs,
    gate_config: QualityGateConfig,
) -> QualityReport:
    """Evaluate every configured gate and assemble the quality report."""
    results: list[GateResult] = []

    for name in sorted(gate_config.gates):
        value = gate_config.gates[name]

        if name in THRESHOLD_GATES:
            results.append(_evaluate_fixture_minimums(name, inputs, gate_config))
            continue
        if name in LIST_GATES:
            results.append(_evaluate_maturity_allowed(inputs, gate_config))
            continue
        if not isinstance(value, bool):
            results.append(
                _gate(name, True, f"unrecognised gate value {value!r}; not enforced", enabled=False)
            )
            continue
        if not value:
            results.append(_gate(name, True, "gate is disabled in configuration", enabled=False))
            continue

        if name == "safe_yaml_load":
            results.append(_evaluate_safe_yaml_load(inputs))
        elif name in ("all_positive_must_match", "all_negative_must_reject"):
            results.append(_evaluate_expectation_gate(name, inputs))
        elif name == "unsupported_not_counted_as_pass":
            results.append(_evaluate_unsupported_not_counted(inputs))
        elif name == "conversion_status_recorded":
            results.append(_evaluate_conversion_recorded(inputs))
        else:
            results.append(_evaluate_finding_gate(name, inputs))

    return QualityReport(
        gates=tuple(results),
        generated_at=utc_now_iso(),
        rules_examined=len(inputs.catalog),
    )


def gate_summary(report: QualityReport) -> dict[str, Any]:
    """Summarise a quality report for console output."""
    enabled = [gate for gate in report.gates if gate.enabled]
    return {
        "passed": report.passed,
        "total_gates": len(report.gates),
        "enabled_gates": len(enabled),
        "failed_gates": [gate.gate for gate in report.failed_gates],
        "finding_count": len(report.all_findings()),
    }


__all__ = [
    "COMPUTED_GATES",
    "GATES_FILENAME",
    "LIST_GATES",
    "THRESHOLD_GATES",
    "GateInputs",
    "QualityGateConfig",
    "apply_gates",
    "gate_summary",
    "load_quality_gates",
]
