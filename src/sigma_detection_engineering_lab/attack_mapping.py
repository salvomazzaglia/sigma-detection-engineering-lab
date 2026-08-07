"""Validating ATT&CK mappings against the vendored catalog.

The governing rule is that an unverifiable identifier is worse than no
identifier. A rule with no ATT&CK mapping and a written reason is honest and
passes. A rule citing ``T9999`` is fabricated coverage: it inflates every
Navigator layer and coverage metric downstream, so it fails.

Three consistency checks run beyond simple existence:

* deprecated and revoked ATT&CK objects are flagged, since mapping to them
  misrepresents current coverage;
* a rule's Sigma ``attack.`` tags and its sidecar mapping must agree, so the two
  places a technique can be recorded cannot drift apart;
* a declared tactic must actually be one the technique belongs to.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from sigma_detection_engineering_lab.attack_catalog import (
    AttackCatalog,
    is_well_formed,
    tactic_names_from_tags,
    technique_ids_from_tags,
)
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    AttackMapping,
    FindingCategory,
    Rule,
    SidecarMetadata,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

MIN_REASON_LENGTH: Final[int] = 24

_TYPE_LABELS: Final[dict[str, str]] = {
    "techniques": "technique",
    "tactics": "tactic",
    "detection_strategies": "detection strategy",
    "analytics": "analytic",
    "data_components": "data component",
}


def _finding(
    code: str,
    severity: Severity,
    subject: str,
    message: str,
    *,
    path: str | None = None,
    gate: str | None = None,
    remediation: str | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        category=FindingCategory.ATTACK,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        gate=gate,
        remediation=remediation,
    )


def validate_identifiers(
    identifiers: Sequence[str],
    object_type: str,
    *,
    catalog: AttackCatalog,
    subject: str,
    path: str | None,
) -> list[ValidationFinding]:
    """Check a list of identifiers of one type for shape, existence, and currency."""
    label = _TYPE_LABELS[object_type]
    findings: list[ValidationFinding] = []
    seen: set[str] = set()

    for identifier in identifiers:
        text = identifier.strip()
        if not text:
            findings.append(
                _finding(
                    "SDEL-ATT-001",
                    Severity.MEDIUM,
                    subject,
                    f"empty {label} identifier in the ATT&CK mapping",
                    path=path,
                    gate="valid_attack_tags",
                )
            )
            continue

        key = text.upper()
        if key in seen:
            findings.append(
                _finding(
                    "SDEL-ATT-002",
                    Severity.LOW,
                    subject,
                    f"{label} {text!r} is listed more than once",
                    path=path,
                )
            )
            continue
        seen.add(key)

        if not is_well_formed(object_type, text):
            findings.append(
                _finding(
                    "SDEL-ATT-003",
                    Severity.HIGH,
                    subject,
                    f"{label} identifier {text!r} is not a well-formed ATT&CK identifier",
                    path=path,
                    gate="verified_attack_technique_ids",
                )
            )
            continue

        if not catalog.is_available:
            findings.append(
                _finding(
                    "SDEL-ATT-004",
                    Severity.MEDIUM,
                    subject,
                    f"{label} {text!r} could not be verified: the vendored ATT&CK catalog "
                    "is empty or missing",
                    path=path,
                    gate="verified_attack_technique_ids",
                    remediation=(
                        "Vendor the ATT&CK subset into the configured data/attack directory."
                    ),
                )
            )
            continue

        obj = catalog.get(object_type, text)
        if obj is None:
            findings.append(
                _finding(
                    "SDEL-ATT-005",
                    Severity.CRITICAL,
                    subject,
                    f"{label} {text!r} does not exist in the vendored ATT&CK catalog "
                    f"(version {catalog.attack_version or 'unknown'}); inventing identifiers "
                    "fabricates coverage",
                    path=path,
                    gate="verified_attack_technique_ids",
                    remediation=(
                        "Use an identifier from the official ATT&CK release, or leave the "
                        "mapping empty and state the reason."
                    ),
                )
            )
            continue

        if not obj.is_active:
            state = "revoked" if obj.revoked else "deprecated"
            findings.append(
                _finding(
                    "SDEL-ATT-006",
                    Severity.HIGH,
                    subject,
                    f"{label} {text!r} is {state} in ATT&CK {catalog.attack_version or 'unknown'}",
                    path=path,
                    gate="verified_attack_technique_ids",
                    remediation="Map to the current replacement object.",
                )
            )
    return findings


def validate_mapping(
    mapping: AttackMapping,
    *,
    catalog: AttackCatalog,
    subject: str,
    path: str | None = None,
) -> list[ValidationFinding]:
    """Validate one sidecar ATT&CK mapping in full."""
    if mapping.is_empty:
        reason = (mapping.reason or "").strip()
        if not reason:
            return [
                _finding(
                    "SDEL-ATT-010",
                    Severity.HIGH,
                    subject,
                    "ATT&CK mapping is empty and gives no reason",
                    path=path,
                    gate="verified_attack_technique_ids",
                    remediation=(
                        "Either map the detection to ATT&CK, or set 'reason' explaining why "
                        "no technique applies. An unexplained gap is indistinguishable from "
                        "an oversight."
                    ),
                )
            ]
        if len(reason) < MIN_REASON_LENGTH:
            return [
                _finding(
                    "SDEL-ATT-011",
                    Severity.MEDIUM,
                    subject,
                    f"ATT&CK mapping is empty and its reason is only {len(reason)} "
                    f"characters; at least {MIN_REASON_LENGTH} are expected",
                    path=path,
                    gate="verified_attack_technique_ids",
                )
            ]
        return []

    findings: list[ValidationFinding] = []
    for object_type, identifiers in (
        ("techniques", mapping.techniques),
        ("tactics", mapping.tactics),
        ("detection_strategies", mapping.detection_strategies),
        ("analytics", mapping.analytics),
        ("data_components", mapping.data_components),
    ):
        findings.extend(
            validate_identifiers(
                identifiers,
                object_type,
                catalog=catalog,
                subject=subject,
                path=path,
            )
        )

    findings.extend(
        _validate_tactic_consistency(mapping, catalog=catalog, subject=subject, path=path)
    )
    return findings


def _validate_tactic_consistency(
    mapping: AttackMapping,
    *,
    catalog: AttackCatalog,
    subject: str,
    path: str | None,
) -> list[ValidationFinding]:
    """Check that declared tactics are ones the declared techniques belong to."""
    if not catalog.is_available or not mapping.techniques or not mapping.tactics:
        return []

    valid_tactics: set[str] = set()
    for technique_id in mapping.techniques:
        technique = catalog.get_technique(technique_id)
        if technique is None:
            technique = catalog.get_technique(catalog.parent_technique(technique_id))
        if technique is None:
            continue
        valid_tactics.update(item.lower() for item in technique.tactics)

    if not valid_tactics:
        return []

    findings: list[ValidationFinding] = []
    for declared in mapping.tactics:
        resolved = catalog.get_tactic(declared)
        candidates = {declared.strip().lower()}
        if resolved is not None:
            if resolved.shortname:
                candidates.add(resolved.shortname.lower())
            if resolved.name:
                candidates.add(resolved.name.lower().replace(" ", "-"))
        if not candidates & valid_tactics:
            findings.append(
                _finding(
                    "SDEL-ATT-012",
                    Severity.MEDIUM,
                    subject,
                    f"tactic {declared!r} is not associated with any mapped technique "
                    f"({', '.join(mapping.techniques)})",
                    path=path,
                    gate="valid_attack_tags",
                )
            )
    return findings


def validate_rule_tags(
    rule: Rule,
    *,
    catalog: AttackCatalog,
) -> list[ValidationFinding]:
    """Validate the ATT&CK identifiers embedded in a rule's Sigma tags."""
    findings: list[ValidationFinding] = []
    techniques = technique_ids_from_tags(rule.tags)
    tactics = tactic_names_from_tags(rule.tags)

    findings.extend(
        validate_identifiers(
            techniques,
            "techniques",
            catalog=catalog,
            subject=rule.catalog_id,
            path=rule.relative_path,
        )
    )
    findings.extend(
        validate_identifiers(
            tactics,
            "tactics",
            catalog=catalog,
            subject=rule.catalog_id,
            path=rule.relative_path,
        )
    )
    return findings


def validate_tag_sidecar_agreement(
    rule: Rule,
    sidecar: SidecarMetadata,
) -> list[ValidationFinding]:
    """Require the rule's tags and its sidecar mapping to describe the same techniques."""
    tagged = set(technique_ids_from_tags(rule.tags))
    declared = {item.strip().upper() for item in sidecar.attack_mapping.techniques}

    findings: list[ValidationFinding] = []
    missing_from_sidecar = sorted(tagged - declared)
    missing_from_tags = sorted(declared - tagged)

    if missing_from_sidecar:
        findings.append(
            _finding(
                "SDEL-ATT-020",
                Severity.MEDIUM,
                rule.catalog_id,
                f"technique(s) tagged on the rule but absent from the sidecar mapping: "
                f"{', '.join(missing_from_sidecar)}",
                path=sidecar.relative_path,
                gate="valid_attack_tags",
            )
        )
    if missing_from_tags:
        findings.append(
            _finding(
                "SDEL-ATT-021",
                Severity.MEDIUM,
                rule.catalog_id,
                f"technique(s) in the sidecar mapping but not tagged on the rule: "
                f"{', '.join(missing_from_tags)}",
                path=rule.relative_path,
                gate="valid_attack_tags",
                remediation="Add the matching 'attack.<technique>' tag to the rule.",
            )
        )
    return findings


def validate_catalog(
    rules: RuleCatalog,
    metadata: MetadataSet,
    attack: AttackCatalog,
) -> list[ValidationFinding]:
    """Validate ATT&CK mappings across every rule and sidecar."""
    findings: list[ValidationFinding] = []
    indexed = metadata.by_catalog_id()

    for source, message in attack.load_errors:
        findings.append(
            _finding(
                "SDEL-ATT-000",
                Severity.MEDIUM,
                source,
                f"ATT&CK catalog could not be fully loaded: {message}",
                path=source,
                gate="verified_attack_technique_ids",
            )
        )

    for rule in rules:
        findings.extend(validate_rule_tags(rule, catalog=attack))
        sidecar = indexed.get(rule.catalog_id)
        if sidecar is None:
            continue
        findings.extend(
            validate_mapping(
                sidecar.attack_mapping,
                catalog=attack,
                subject=rule.catalog_id,
                path=sidecar.relative_path,
            )
        )
        findings.extend(validate_tag_sidecar_agreement(rule, sidecar))
    return findings


def mapped_techniques(metadata: MetadataSet) -> dict[str, int]:
    """Count how many rules map to each technique, for coverage and Navigator."""
    counts: dict[str, int] = {}
    for sidecar in metadata.sidecars:
        for technique in sidecar.attack_mapping.techniques:
            key = technique.strip().upper()
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def mapped_tactics(metadata: MetadataSet) -> dict[str, int]:
    """Count how many rules map to each tactic."""
    counts: dict[str, int] = {}
    for sidecar in metadata.sidecars:
        for tactic in sidecar.attack_mapping.tactics:
            key = tactic.strip().lower()
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "MIN_REASON_LENGTH",
    "mapped_tactics",
    "mapped_techniques",
    "validate_catalog",
    "validate_identifiers",
    "validate_mapping",
    "validate_rule_tags",
    "validate_tag_sidecar_agreement",
]
