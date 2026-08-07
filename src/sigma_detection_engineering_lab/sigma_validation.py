"""Structural validation of Sigma rules.

Validation runs at two levels. pySigma is asked whether the rule is a valid Sigma
document at all, which keeps the project honest against the upstream
specification. This module then checks the rule against the laboratory's own
evaluator profile: a rule that pySigma accepts but whose condition or modifiers
fall outside the documented subset cannot be behaviorally tested here, and saying
so is more useful than testing it incorrectly.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sigma_detection_engineering_lab.condition_parser import parse_condition
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.correlation_engine import parse_correlation
from sigma_detection_engineering_lab.errors import (
    ConditionSyntaxError,
    CorrelationError,
    MatcherError,
    UnsupportedConditionError,
    UnsupportedModifierError,
)
from sigma_detection_engineering_lab.event_matcher import (
    DEFAULT_OPTIONS,
    DetectionMatcher,
    MatchOptions,
)
from sigma_detection_engineering_lab.models import (
    FindingCategory,
    Rule,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import (
    correlation_base_documents,
    parse_with_pysigma,
    pysigma_status,
)
from sigma_detection_engineering_lab.severities import Severity

MAX_TITLE_LENGTH = 256
MIN_DESCRIPTION_LENGTH = 32
MAX_DESCRIPTION_LENGTH = 4096


def _finding(
    code: str,
    severity: Severity,
    rule: Rule,
    message: str,
    *,
    gate: str | None = None,
    remediation: str | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        category=FindingCategory.STRUCTURE,
        severity=severity,
        subject=rule.catalog_id,
        message=message,
        path=rule.relative_path,
        gate=gate,
        remediation=remediation,
    )


def _is_iso_date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")  # noqa: DTZ007 - a bare date has no zone
    except ValueError:
        return False
    return True


def _parse_iso_date(value: str) -> date | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()  # noqa: DTZ007
    except ValueError:
        return None


def validate_dates(rule: Rule) -> list[ValidationFinding]:
    """Check that ``date`` and ``modified`` are present, well formed, and ordered."""
    findings: list[ValidationFinding] = []

    if not rule.date:
        findings.append(
            _finding(
                "SDEL-STR-020",
                Severity.HIGH,
                rule,
                "rule has no 'date' field",
                gate="valid_date",
                remediation="Add 'date: YYYY-MM-DD' recording when the rule was authored.",
            )
        )
    elif not _is_iso_date(rule.date):
        findings.append(
            _finding(
                "SDEL-STR-021",
                Severity.HIGH,
                rule,
                f"'date' value {rule.date!r} is not an ISO 8601 calendar date",
                gate="valid_date",
                remediation="Use the YYYY-MM-DD form, for example 2026-08-07.",
            )
        )

    if rule.modified:
        if not _is_iso_date(rule.modified):
            findings.append(
                _finding(
                    "SDEL-STR-022",
                    Severity.HIGH,
                    rule,
                    f"'modified' value {rule.modified!r} is not an ISO 8601 calendar date",
                    gate="valid_date",
                )
            )
        elif rule.date and _is_iso_date(rule.date):
            authored = _parse_iso_date(rule.date)
            changed = _parse_iso_date(rule.modified)
            if authored and changed and changed < authored:
                findings.append(
                    _finding(
                        "SDEL-STR-023",
                        Severity.MEDIUM,
                        rule,
                        f"'modified' ({rule.modified}) precedes 'date' ({rule.date})",
                        gate="valid_date",
                    )
                )
    return findings


def validate_core_fields(rule: Rule) -> list[ValidationFinding]:
    """Check title, description, and logsource against the specification."""
    findings: list[ValidationFinding] = []

    if len(rule.title) > MAX_TITLE_LENGTH:
        findings.append(
            _finding(
                "SDEL-STR-001",
                Severity.MEDIUM,
                rule,
                f"title is {len(rule.title)} characters; the specification recommends at most "
                f"{MAX_TITLE_LENGTH}",
            )
        )

    if not rule.description:
        findings.append(
            _finding(
                "SDEL-STR-002",
                Severity.HIGH,
                rule,
                "rule has no description",
                remediation="Describe what the rule detects and why the behaviour is suspicious.",
            )
        )
    elif len(rule.description) < MIN_DESCRIPTION_LENGTH:
        findings.append(
            _finding(
                "SDEL-STR-003",
                Severity.MEDIUM,
                rule,
                f"description is only {len(rule.description)} characters; at least "
                f"{MIN_DESCRIPTION_LENGTH} are expected for a reviewable rule",
            )
        )
    elif len(rule.description) > MAX_DESCRIPTION_LENGTH:
        findings.append(
            _finding(
                "SDEL-STR-004",
                Severity.LOW,
                rule,
                f"description is {len(rule.description)} characters, exceeding "
                f"{MAX_DESCRIPTION_LENGTH}",
            )
        )

    # A correlation rule selects the base rules it aggregates, not a log source;
    # the Sigma specification gives it no logsource block at all.
    if rule.logsource.is_empty and not rule.is_correlation:
        findings.append(
            _finding(
                "SDEL-STR-005",
                Severity.HIGH,
                rule,
                "logsource specifies none of category, product, or service",
                gate="valid_logsource",
                remediation="Add at least a product and category so the rule can be targeted.",
            )
        )
    return findings


def validate_detection(
    rule: Rule,
    *,
    options: MatchOptions = DEFAULT_OPTIONS,
) -> list[ValidationFinding]:
    """Compile the detection block and report anything outside the lab subset."""
    findings: list[ValidationFinding] = []

    if rule.is_correlation:
        return findings

    if not rule.detection:
        return [
            _finding(
                "SDEL-STR-010",
                Severity.CRITICAL,
                rule,
                "rule has an empty detection block",
            )
        ]

    if "condition" not in rule.detection:
        return [
            _finding(
                "SDEL-STR-011",
                Severity.CRITICAL,
                rule,
                "detection block has no 'condition'",
            )
        ]

    try:
        condition = parse_condition(
            rule.detection["condition"], source=f"{rule.catalog_id}.detection.condition"
        )
    except UnsupportedConditionError as exc:
        return [
            _finding(
                "SDEL-STR-012",
                Severity.HIGH,
                rule,
                f"condition uses an unsupported construct: {exc}",
                remediation=(
                    "Rewrite the condition within the documented subset, or move the logic "
                    "into a correlation rule."
                ),
            )
        ]
    except ConditionSyntaxError as exc:
        return [
            _finding(
                "SDEL-STR-013",
                Severity.CRITICAL,
                rule,
                f"condition is syntactically invalid: {exc}",
            )
        ]

    try:
        matcher = DetectionMatcher(
            rule.detection, options=options, source=f"{rule.catalog_id}.detection"
        )
    except UnsupportedModifierError as exc:
        return [
            _finding(
                "SDEL-STR-014",
                Severity.HIGH,
                rule,
                f"detection uses an unsupported modifier: {exc}",
                remediation=(
                    "Use only the modifiers listed in config/evaluator-profile.json, or "
                    "document the rule as not behaviorally testable."
                ),
            )
        ]
    except MatcherError as exc:
        return [
            _finding(
                "SDEL-STR-015",
                Severity.CRITICAL,
                rule,
                f"detection block could not be compiled: {exc}",
            )
        ]

    referenced = set(condition.referenced_selections(matcher.selection_names))
    unused = [name for name in matcher.selection_names if name not in referenced]
    if unused:
        findings.append(
            _finding(
                "SDEL-STR-016",
                Severity.MEDIUM,
                rule,
                f"selection(s) defined but never referenced by the condition: {', '.join(unused)}",
                remediation="Remove the unused selection or reference it from the condition.",
            )
        )
    return findings


def validate_correlation(
    rule: Rule,
    *,
    catalog: RuleCatalog | None = None,
) -> list[ValidationFinding]:
    """Validate a correlation block and check that its referenced rules resolve."""
    if not rule.is_correlation or rule.correlation is None:
        return []

    try:
        definition = parse_correlation(rule.correlation, source=f"{rule.catalog_id}.correlation")
    except CorrelationError as exc:
        return [
            ValidationFinding(
                code="SDEL-COR-001",
                category=FindingCategory.CORRELATION,
                severity=Severity.CRITICAL,
                subject=rule.catalog_id,
                message=f"correlation block is invalid: {exc}",
                path=rule.relative_path,
            )
        ]

    findings: list[ValidationFinding] = []
    inline = correlation_base_documents(rule)
    for reference in definition.rules:
        if reference in inline:
            continue
        if catalog is not None and catalog.resolve(reference) is not None:
            continue
        findings.append(
            ValidationFinding(
                code="SDEL-COR-002",
                category=FindingCategory.CORRELATION,
                severity=Severity.CRITICAL,
                subject=rule.catalog_id,
                message=(
                    f"correlation references rule {reference!r}, which is neither a base "
                    f"document in this file nor a rule in the catalog"
                ),
                path=rule.relative_path,
                remediation=(
                    "Add the base rule as a document in this file, or reference an existing "
                    "rule by its name or UUID."
                ),
            )
        )
    return findings


def validate_with_pysigma(rule: Rule) -> list[ValidationFinding]:
    """Ask pySigma to parse the rule and turn its verdict into findings."""
    if not rule.raw_text:
        return []

    result = parse_with_pysigma(rule.raw_text, source=rule.relative_path)

    if not result.attempted:
        return [
            _finding(
                "SDEL-STR-030",
                Severity.MEDIUM,
                rule,
                "pySigma is not installed, so upstream specification parsing was skipped",
                gate="pysigma_parse",
                remediation="Install the pinned dependencies to enable upstream validation.",
            )
        ]

    if not result.succeeded:
        detail = "; ".join(result.errors) or result.detail
        return [
            _finding(
                "SDEL-STR-031",
                Severity.CRITICAL,
                rule,
                f"pySigma rejected the rule: {detail}",
                gate="pysigma_parse",
            )
        ]
    return []


def validate_rule(
    rule: Rule,
    *,
    config: LabConfig,
    options: MatchOptions = DEFAULT_OPTIONS,
    catalog: RuleCatalog | None = None,
    run_pysigma: bool = True,
) -> list[ValidationFinding]:
    """Run every structural check against one rule."""
    findings: list[ValidationFinding] = []
    findings.extend(validate_core_fields(rule))
    findings.extend(validate_dates(rule))
    findings.extend(validate_detection(rule, options=options))
    findings.extend(validate_correlation(rule, catalog=catalog))
    if run_pysigma:
        findings.extend(validate_with_pysigma(rule))
    return findings


def validate_catalog(
    catalog: RuleCatalog,
    *,
    config: LabConfig,
    options: MatchOptions = DEFAULT_OPTIONS,
    run_pysigma: bool = True,
) -> list[ValidationFinding]:
    """Run structural validation across the whole catalog, including uniqueness."""
    findings: list[ValidationFinding] = list(catalog.uniqueness_findings())
    for rule in catalog:
        findings.extend(
            validate_rule(
                rule,
                config=config,
                options=options,
                catalog=catalog,
                run_pysigma=run_pysigma,
            )
        )
    return findings


def structural_summary(catalog: RuleCatalog) -> dict[str, Any]:
    """Summarise the environment used for structural validation."""
    status = pysigma_status()
    return {
        "rules_examined": len(catalog),
        "pysigma_available": status.available,
        "pysigma_version": status.version,
        "pysigma_error": status.error,
    }


__all__ = [
    "MAX_DESCRIPTION_LENGTH",
    "MAX_TITLE_LENGTH",
    "MIN_DESCRIPTION_LENGTH",
    "structural_summary",
    "validate_catalog",
    "validate_core_fields",
    "validate_correlation",
    "validate_dates",
    "validate_detection",
    "validate_rule",
    "validate_with_pysigma",
]
