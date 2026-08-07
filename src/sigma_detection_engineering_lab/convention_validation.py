"""Project authoring conventions, enforced on the main rule catalog.

These rules are stricter than the Sigma specification on purpose. They exist so
the catalog stays provably original, attributable, and honest about its own
maturity:

* every rule is authored by the declared project author and licensed MIT, so
  provenance is unambiguous and no upstream content can be mistaken for original
  work;
* every rule carries a valid UUID and a conventional filename;
* ``status`` is ``experimental`` or ``test`` only. ``stable`` is blocked outright
  because it asserts production validation that synthetic testing cannot support;
* ``falsepositives`` must be specific. "Unknown" tells an analyst nothing at 3am;
* ``references`` must be non-empty, so a reviewer can trace the reasoning.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from typing import Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.models import (
    FindingCategory,
    Rule,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import (
    RULE_FILENAME_PATTERN,
    is_valid_rule_filename,
)
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import (
    RETIRED_STATUSES,
    SigmaStatus,
)

ALLOWED_UUID_VERSIONS: Final[frozenset[int]] = frozenset({4, 5})

BANNED_FALSEPOSITIVES: Final[frozenset[str]] = frozenset(
    {
        "unknown",
        "none",
        "n/a",
        "na",
        "legitimate activity",
        "legitimate use",
        "administrator activity",
        "admin activity",
        "normal activity",
        "rare",
        "false positives",
        "tbd",
    }
)
"""Placeholder false positives that convey no tuning information."""

MIN_FALSEPOSITIVE_LENGTH: Final[int] = 12
MIN_FALSEPOSITIVES: Final[int] = 1
MIN_REFERENCES: Final[int] = 1

TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")

REFERENCE_SCHEMES: Final[tuple[str, ...]] = ("https://", "http://")


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
        category=FindingCategory.CONVENTION,
        severity=severity,
        subject=rule.catalog_id,
        message=message,
        path=rule.relative_path,
        gate=gate,
        remediation=remediation,
    )


def validate_author(rule: Rule, config: LabConfig) -> list[ValidationFinding]:
    """Require the declared project author on every rule."""
    if not rule.author:
        return [
            _finding(
                "SDEL-CNV-001",
                Severity.HIGH,
                rule,
                "rule has no 'author' field",
                gate="required_metadata",
                remediation=f"Set 'author: {config.required_authors[0]}'.",
            )
        ]

    declared = [part.strip() for part in rule.author.split(",") if part.strip()]
    missing = [name for name in config.required_authors if name not in declared]
    if missing:
        return [
            _finding(
                "SDEL-CNV-002",
                Severity.HIGH,
                rule,
                f"author {rule.author!r} does not include the required author(s): "
                f"{', '.join(missing)}",
                gate="required_metadata",
                remediation=(
                    "This catalog contains original rules only; attribute them to the "
                    "project author."
                ),
            )
        ]
    return []


def validate_license(rule: Rule, config: LabConfig) -> list[ValidationFinding]:
    """Require an explicit, correct licence declaration."""
    if not rule.license:
        return [
            _finding(
                "SDEL-CNV-003",
                Severity.HIGH,
                rule,
                "rule has no 'license' field",
                gate="required_metadata",
                remediation=f"Set 'license: {config.license}'.",
            )
        ]
    if rule.license.strip().upper() != config.license.strip().upper():
        return [
            _finding(
                "SDEL-CNV-004",
                Severity.HIGH,
                rule,
                f"license {rule.license!r} does not match the project licence {config.license!r}",
                gate="required_metadata",
            )
        ]
    return []


def validate_uuid(rule: Rule) -> list[ValidationFinding]:
    """Require a syntactically valid, canonically formatted UUID."""
    if not rule.rule_id:
        return [
            _finding(
                "SDEL-CNV-010",
                Severity.CRITICAL,
                rule,
                "rule has no 'id' field",
                gate="unique_uuid",
                remediation="Generate a UUIDv4 and set it as the rule 'id'.",
            )
        ]
    try:
        parsed = uuid.UUID(rule.rule_id)
    except ValueError:
        return [
            _finding(
                "SDEL-CNV-011",
                Severity.CRITICAL,
                rule,
                f"rule id {rule.rule_id!r} is not a valid UUID",
                gate="unique_uuid",
            )
        ]

    findings: list[ValidationFinding] = []
    if str(parsed) != rule.rule_id.strip().lower():
        findings.append(
            _finding(
                "SDEL-CNV-012",
                Severity.LOW,
                rule,
                f"rule id {rule.rule_id!r} is not in canonical lowercase hyphenated form",
                remediation=f"Use {parsed}.",
            )
        )
    # Version 4 is random and version 5 is a name-based hash. Both give a stable,
    # collision-resistant identifier; version 5 additionally makes rule IDs
    # reproducible from the rule's name, which is what a generated catalog wants.
    if parsed.version not in ALLOWED_UUID_VERSIONS:
        expected = " or ".join(str(version) for version in sorted(ALLOWED_UUID_VERSIONS))
        findings.append(
            _finding(
                "SDEL-CNV-013",
                Severity.MEDIUM,
                rule,
                f"rule id {rule.rule_id!r} is UUID version {parsed.version}; "
                f"version {expected} is expected",
            )
        )
    return findings


def validate_filename(rule: Rule) -> list[ValidationFinding]:
    """Require the lowercase, separator-delimited ``.yml`` filename convention."""
    if is_valid_rule_filename(rule.path):
        return []
    return [
        _finding(
            "SDEL-CNV-020",
            Severity.MEDIUM,
            rule,
            f"filename {rule.path.name!r} does not match the convention "
            f"{RULE_FILENAME_PATTERN.pattern}",
            gate="valid_filename",
            remediation="Use lowercase words separated by underscores, ending in '.yml'.",
        )
    ]


def validate_status(rule: Rule, config: LabConfig) -> list[ValidationFinding]:
    """Enforce the status policy, including the hard block on ``stable``."""
    findings: list[ValidationFinding] = []

    if rule.status in config.blocked_sigma_statuses:
        findings.append(
            _finding(
                "SDEL-CNV-030",
                Severity.CRITICAL,
                rule,
                f"status {rule.status} is blocked in the main catalog because it asserts "
                "production validation that synthetic testing cannot substantiate",
                gate="block_stable_status",
                remediation="Use 'experimental' or 'test'.",
            )
        )
        return findings

    if rule.status not in config.allowed_sigma_statuses:
        severity = Severity.HIGH if rule.status in RETIRED_STATUSES else Severity.CRITICAL
        allowed = ", ".join(sorted(str(status) for status in config.allowed_sigma_statuses))
        findings.append(
            _finding(
                "SDEL-CNV-031",
                severity,
                rule,
                f"status {rule.status} is not permitted in the main catalog; allowed: {allowed}",
                gate="status_experimental_or_test",
            )
        )
    return findings


def validate_references(rule: Rule) -> list[ValidationFinding]:
    """Require at least one traceable reference."""
    if len(rule.references) < MIN_REFERENCES:
        return [
            _finding(
                "SDEL-CNV-040",
                Severity.HIGH,
                rule,
                "rule has no 'references'",
                gate="non_empty_references",
                remediation=(
                    "Cite the technique documentation or research that motivated the detection."
                ),
            )
        ]

    findings: list[ValidationFinding] = []
    for index, reference in enumerate(rule.references):
        text = reference.strip()
        if not text:
            findings.append(
                _finding(
                    "SDEL-CNV-041",
                    Severity.MEDIUM,
                    rule,
                    f"references[{index}] is empty",
                    gate="non_empty_references",
                )
            )
        elif not text.lower().startswith(REFERENCE_SCHEMES):
            findings.append(
                _finding(
                    "SDEL-CNV-042",
                    Severity.LOW,
                    rule,
                    f"references[{index}] {text!r} is not an http(s) URL",
                )
            )
    return findings


def validate_falsepositives(rule: Rule) -> list[ValidationFinding]:
    """Require false positives that actually guide tuning."""
    if len(rule.falsepositives) < MIN_FALSEPOSITIVES:
        return [
            _finding(
                "SDEL-CNV-050",
                Severity.HIGH,
                rule,
                "rule has no 'falsepositives'",
                gate="non_empty_falsepositives",
                remediation=(
                    "Describe the benign activity most likely to trigger this rule, "
                    "specifically enough for an analyst to recognise it."
                ),
            )
        ]

    findings: list[ValidationFinding] = []
    for index, entry in enumerate(rule.falsepositives):
        text = entry.strip()
        lowered = text.lower().rstrip(".")
        if not text:
            findings.append(
                _finding(
                    "SDEL-CNV-051",
                    Severity.HIGH,
                    rule,
                    f"falsepositives[{index}] is empty",
                    gate="non_empty_falsepositives",
                )
            )
        elif lowered in BANNED_FALSEPOSITIVES:
            findings.append(
                _finding(
                    "SDEL-CNV-052",
                    Severity.HIGH,
                    rule,
                    f"falsepositives[{index}] {text!r} is a placeholder that gives an analyst "
                    "no tuning information",
                    gate="specific_falsepositives",
                    remediation=(
                        "Name the concrete benign scenario, for example the tool, account "
                        "type, or maintenance window involved."
                    ),
                )
            )
        elif len(text) < MIN_FALSEPOSITIVE_LENGTH:
            findings.append(
                _finding(
                    "SDEL-CNV-053",
                    Severity.MEDIUM,
                    rule,
                    f"falsepositives[{index}] {text!r} is too short to be specific "
                    f"(under {MIN_FALSEPOSITIVE_LENGTH} characters)",
                    gate="specific_falsepositives",
                )
            )
    return findings


def validate_tags(rule: Rule) -> list[ValidationFinding]:
    """Check tag formatting. Semantic ATT&CK validation lives in attack_mapping."""
    findings: list[ValidationFinding] = []
    seen: set[str] = set()
    for index, tag in enumerate(rule.tags):
        text = tag.strip()
        if not TAG_PATTERN.match(text):
            findings.append(
                _finding(
                    "SDEL-CNV-060",
                    Severity.MEDIUM,
                    rule,
                    f"tags[{index}] {tag!r} is not lowercase dot/dash/underscore separated",
                    gate="valid_attack_tags",
                )
            )
        if text.lower() in seen:
            findings.append(
                _finding(
                    "SDEL-CNV-061",
                    Severity.LOW,
                    rule,
                    f"tags[{index}] {tag!r} is duplicated",
                )
            )
        seen.add(text.lower())
    return findings


def validate_title_uniqueness(catalog: RuleCatalog) -> list[ValidationFinding]:
    """Two rules with the same title make every report ambiguous."""
    seen: dict[str, Rule] = {}
    findings: list[ValidationFinding] = []
    for rule in catalog:
        key = rule.title.strip().lower()
        previous = seen.get(key)
        if previous is not None:
            findings.append(
                _finding(
                    "SDEL-CNV-070",
                    Severity.MEDIUM,
                    rule,
                    f"title {rule.title!r} duplicates {previous.relative_path}",
                )
            )
        else:
            seen[key] = rule
    return findings


def validate_rule(rule: Rule, *, config: LabConfig) -> list[ValidationFinding]:
    """Run every convention check against one rule."""
    findings: list[ValidationFinding] = []
    findings.extend(validate_author(rule, config))
    findings.extend(validate_license(rule, config))
    findings.extend(validate_uuid(rule))
    findings.extend(validate_filename(rule))
    findings.extend(validate_status(rule, config))
    findings.extend(validate_references(rule))
    findings.extend(validate_falsepositives(rule))
    findings.extend(validate_tags(rule))
    return findings


def validate_catalog(catalog: RuleCatalog, *, config: LabConfig) -> list[ValidationFinding]:
    """Run convention validation across the whole catalog."""
    findings: list[ValidationFinding] = []
    for rule in catalog:
        findings.extend(validate_rule(rule, config=config))
    findings.extend(validate_title_uniqueness(catalog))
    return findings


def banned_falsepositives(extra: Sequence[str] = ()) -> frozenset[str]:
    """Return the banned placeholder set, extended with configured entries."""
    return BANNED_FALSEPOSITIVES | {item.strip().lower() for item in extra if item.strip()}


def allowed_statuses(config: LabConfig) -> tuple[SigmaStatus, ...]:
    """Return the configured allowed statuses in a stable order."""
    return tuple(sorted(config.allowed_sigma_statuses, key=lambda status: status.value))


__all__ = [
    "ALLOWED_UUID_VERSIONS",
    "BANNED_FALSEPOSITIVES",
    "MIN_FALSEPOSITIVES",
    "MIN_FALSEPOSITIVE_LENGTH",
    "MIN_REFERENCES",
    "TAG_PATTERN",
    "allowed_statuses",
    "banned_falsepositives",
    "validate_author",
    "validate_catalog",
    "validate_falsepositives",
    "validate_filename",
    "validate_license",
    "validate_references",
    "validate_rule",
    "validate_status",
    "validate_tags",
    "validate_title_uniqueness",
    "validate_uuid",
]
