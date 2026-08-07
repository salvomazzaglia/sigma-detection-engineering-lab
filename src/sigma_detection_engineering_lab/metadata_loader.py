"""Loading and validating rule sidecar metadata.

A sidecar lives at ``metadata/rules/<catalog_id>.json`` and records what the Sigma
specification has no field for: the hypothesis the detection encodes, the
telemetry it needs, its ATT&CK mapping, its evidence maturity, and its known
limitations.

The sidecar is also where a rule's catalog identifier comes from. Rule filenames
are descriptive, which is good for reading a repository and useless as a stable
key, so the binding runs the other way: each sidecar names a ``sigma_rule_id``,
that UUID is matched against the rule document's ``id``, and the sidecar's
``catalog_id`` becomes the rule's identity everywhere else in the laboratory.
A rule whose UUID no sidecar claims has no catalog identifier, which is reported
rather than papered over with a filename-derived guess.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import (
    MetadataError,
    PathSafetyError,
    YamlSafetyError,
)
from sigma_detection_engineering_lab.models import (
    AttackMapping,
    FindingCategory,
    Rule,
    SidecarMetadata,
    TelemetryRequirement,
    ValidationFinding,
)
from sigma_detection_engineering_lab.paths import (
    iter_files,
    relative_display,
    safe_read_text,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import (
    EVIDENCE_UNSUPPORTED_MATURITY,
    Maturity,
    UnknownMaturityError,
    parse_maturity,
)
from sigma_detection_engineering_lab.yaml_loader import load_single_mapping

SIDECAR_GLOBS: Final[tuple[str, ...]] = ("*.yml", "*.yaml", "*.json")

MIN_HYPOTHESIS_LENGTH: Final[int] = 40

CATALOG_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^SDEL-[A-Z]{2,4}-\d{3}$")
"""Catalog identifiers look like ``SDEL-WIN-001``: project, family, sequence."""

KNOWN_SIDECAR_KEYS: Final[frozenset[str]] = frozenset(
    {
        # Identity.
        "schema_version",
        "catalog_id",
        "sigma_rule_id",
        "rule_id",
        "title",
        "platform",
        "rule_family",
        "maturity",
        "version",
        # Detection reasoning.
        "detection_hypothesis",
        "false_positive_strategy",
        "tuning_guidance",
        "test_strategy",
        "validation_notes",
        "known_limitations",
        "minimum_positive_tests",
        "minimum_negative_tests",
        # Telemetry.
        "telemetry_requirements",
        "required_logs",
        "required_channels",
        "required_fields",
        "optional_fields",
        "field_semantics",
        "collection_prerequisites",
        "expected_collection_gaps",
        "normalization_assumptions",
        "ingestion_differences",
        "retention_considerations",
        "expected_volume",
        # ATT&CK.
        "attack_mapping",
        "attack_techniques",
        "attack_tactics",
        "attack_detection_strategies",
        "attack_analytics",
        "attack_data_components",
        "unmapped_defensive_objects_reason",
        "attack_version",
        # Correlation description, mirroring the rule's own correlation block.
        "correlation",
        # Conversion and provenance.
        "supported_backends",
        "unsupported_backend_reasons",
        "related_rules",
        "author",
        "license",
        "created_at",
        "modified_at",
        "synthetic_only",
        "synthetic_fixtures_only",
        "rule_file",
        "fixture_directory",
    }
)


def _string_list(value: object, source: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    raise MetadataError(f"{source}: '{key}' must be a string or a list of strings")


def _parse_telemetry(value: object, source: str) -> tuple[TelemetryRequirement, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise MetadataError(f"{source}: 'telemetry_requirements' must be a list")

    requirements: list[TelemetryRequirement] = []
    for index, entry in enumerate(value):
        label = f"{source}.telemetry_requirements[{index}]"
        if isinstance(entry, str):
            requirements.append(TelemetryRequirement(telemetry_id=entry.strip()))
            continue
        if not isinstance(entry, Mapping):
            raise MetadataError(f"{label}: must be a string or an object")
        telemetry_id = entry.get("telemetry_id") or entry.get("id")
        if not isinstance(telemetry_id, str) or not telemetry_id.strip():
            raise MetadataError(f"{label}: 'telemetry_id' is required")
        requirements.append(
            TelemetryRequirement(
                telemetry_id=telemetry_id.strip(),
                description=str(entry.get("description", "") or ""),
                required_fields=_string_list(
                    entry.get("required_fields"), label, "required_fields"
                ),
                notes=(str(entry["notes"]) if entry.get("notes") else None),
            )
        )
    return tuple(requirements)


def _optional_int(value: object, source: str, key: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise MetadataError(f"{source}: '{key}' must be an integer")
    if value < 0:
        raise MetadataError(f"{source}: '{key}' must not be negative")
    return value


def _reason_mapping(value: object, source: str, key: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise MetadataError(f"{source}: '{key}' must be an object")
    return {str(name): str(reason) for name, reason in value.items()}


def build_sidecar(
    data: Mapping[str, Any],
    *,
    path: Path,
    relative_path: str,
) -> SidecarMetadata:
    """Build a :class:`SidecarMetadata` from a loaded document.

    Both key spellings of the rule UUID are accepted: ``sigma_rule_id`` is the
    project's own schema, and ``rule_id`` is kept working so a hand-written
    sidecar does not become invalid over a rename.

    Raises:
        MetadataError: if a required key is missing or badly typed.
    """
    source = relative_path

    unknown = sorted(set(data) - KNOWN_SIDECAR_KEYS)
    if unknown:
        raise MetadataError(
            f"{source}: unknown key(s): {', '.join(unknown)}; recognised keys are "
            f"{', '.join(sorted(KNOWN_SIDECAR_KEYS))}"
        )

    catalog_id = data.get("catalog_id")
    if not isinstance(catalog_id, str) or not catalog_id.strip():
        raise MetadataError(f"{source}: 'catalog_id' is required")

    rule_id = data.get("sigma_rule_id") or data.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise MetadataError(
            f"{source}: 'sigma_rule_id' is required; it binds this sidecar to the UUID "
            "of the Sigma rule it describes"
        )

    try:
        maturity = parse_maturity(data.get("maturity"))
    except UnknownMaturityError as exc:
        raise MetadataError(f"{source}: {exc}") from exc

    attack_raw = data.get("attack_mapping")
    if attack_raw is not None and not isinstance(attack_raw, Mapping):
        raise MetadataError(f"{source}: 'attack_mapping' must be an object")
    attack_mapping = (
        AttackMapping.from_mapping(attack_raw)
        if attack_raw is not None
        else AttackMapping.from_sidecar(data)
    )

    synthetic_only = data.get("synthetic_fixtures_only", data.get("synthetic_only", True))
    if not isinstance(synthetic_only, bool):
        raise MetadataError(f"{source}: 'synthetic_fixtures_only' must be a boolean")

    required_logs = _string_list(data.get("required_logs"), source, "required_logs")
    required_fields = _string_list(data.get("required_fields"), source, "required_fields")
    declared = _parse_telemetry(data.get("telemetry_requirements"), source)
    if not declared:
        declared = tuple(
            TelemetryRequirement(
                telemetry_id=name,
                description=name,
                required_fields=required_fields,
            )
            for name in required_logs
        )

    # ``known_limitations`` was the original key; the generated sidecars record the
    # same idea under the more specific ``expected_collection_gaps``.
    limitations = _string_list(data.get("known_limitations"), source, "known_limitations")
    if not limitations:
        limitations = _string_list(
            data.get("expected_collection_gaps"), source, "expected_collection_gaps"
        )

    notes = str(data.get("validation_notes", "") or "").strip()
    if not notes:
        notes = str(data.get("test_strategy", "") or "").strip()

    return SidecarMetadata(
        catalog_id=catalog_id.strip(),
        rule_id=rule_id.strip(),
        maturity=maturity,
        path=path,
        relative_path=relative_path,
        title=str(data.get("title", "") or "").strip(),
        detection_hypothesis=str(data.get("detection_hypothesis", "") or "").strip(),
        telemetry_requirements=declared,
        attack_mapping=attack_mapping,
        validation_notes=notes,
        known_limitations=limitations,
        tuning_guidance=_string_list(data.get("tuning_guidance"), source, "tuning_guidance"),
        synthetic_only=synthetic_only,
        platform=_optional_text(data.get("platform")),
        rule_family=_optional_text(data.get("rule_family")),
        required_logs=required_logs,
        required_channels=_string_list(data.get("required_channels"), source, "required_channels"),
        required_fields=required_fields,
        optional_fields=_string_list(data.get("optional_fields"), source, "optional_fields"),
        supported_backends=_string_list(
            data.get("supported_backends"), source, "supported_backends"
        ),
        unsupported_backend_reasons=_reason_mapping(
            data.get("unsupported_backend_reasons"), source, "unsupported_backend_reasons"
        ),
        related_rules=_string_list(data.get("related_rules"), source, "related_rules"),
        minimum_positive_tests=_optional_int(
            data.get("minimum_positive_tests"), source, "minimum_positive_tests"
        ),
        minimum_negative_tests=_optional_int(
            data.get("minimum_negative_tests"), source, "minimum_negative_tests"
        ),
        author=str(data.get("author", "") or "").strip(),
        license=_optional_text(data.get("license")),
        attack_version=_optional_text(data.get("attack_version")),
        rule_file=_optional_text(data.get("rule_file")),
        fixture_directory=_optional_text(data.get("fixture_directory")),
        raw=dict(data),
    )


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def load_sidecar_file(path: Path, *, config: LabConfig) -> SidecarMetadata:
    """Load one sidecar file, in YAML or JSON form.

    Raises:
        MetadataError: on read, parse, or structural failure.
    """
    relative = relative_display(config.root, path)
    try:
        text = safe_read_text(path, max_bytes=config.limits.max_file_bytes)
    except PathSafetyError as exc:
        raise MetadataError(f"{relative}: {exc}") from exc

    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise MetadataError(f"{relative}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise MetadataError(f"{relative}: sidecar root must be an object")
    else:
        try:
            data = load_single_mapping(text, limits=config.limits.yaml_limits(), source=relative)
        except YamlSafetyError as exc:
            raise MetadataError(str(exc)) from exc

    return build_sidecar(data, path=path, relative_path=relative)


@dataclass(frozen=True)
class MetadataSet:
    """Every sidecar found, indexed by catalog identifier."""

    sidecars: tuple[SidecarMetadata, ...] = ()
    failures: tuple[tuple[str, str], ...] = ()

    def by_catalog_id(self) -> dict[str, SidecarMetadata]:
        return {sidecar.catalog_id: sidecar for sidecar in self.sidecars}

    def by_rule_id(self) -> dict[str, SidecarMetadata]:
        """Index sidecars by the Sigma rule UUID they claim, lowercased."""
        return {
            sidecar.rule_id.strip().lower(): sidecar
            for sidecar in self.sidecars
            if sidecar.rule_id.strip()
        }

    def get(self, catalog_id: str) -> SidecarMetadata | None:
        for sidecar in self.sidecars:
            if sidecar.catalog_id == catalog_id:
                return sidecar
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sidecar_count": len(self.sidecars),
            "failure_count": len(self.failures),
            "failures": [{"path": path, "message": message} for path, message in self.failures],
        }


def load_metadata(config: LabConfig, *, directory: Path | None = None) -> MetadataSet:
    """Load every sidecar under the configured metadata directory."""
    target = directory if directory is not None else config.metadata_dir
    if not target.is_dir():
        return MetadataSet()

    sidecars: list[SidecarMetadata] = []
    failures: list[tuple[str, str]] = []
    for path in iter_files(
        config.root,
        target,
        SIDECAR_GLOBS,
        allow_symlinks=config.limits.allow_symlinks,
        max_path_length=config.limits.max_path_length,
    ):
        relative = relative_display(config.root, path)
        try:
            sidecars.append(load_sidecar_file(path, config=config))
        except MetadataError as exc:
            failures.append((relative, str(exc)))

    sidecars.sort(key=lambda sidecar: sidecar.catalog_id)
    return MetadataSet(sidecars=tuple(sidecars), failures=tuple(failures))


def assign_catalog_ids(
    rules: Iterable[Rule],
    metadata: MetadataSet,
) -> tuple[list[Rule], list[ValidationFinding]]:
    """Rebind every rule to the catalog identifier its sidecar declares.

    The rule loader has no way to know a rule's catalog identifier: the filename
    is descriptive prose and the Sigma document carries only a UUID. This is where
    identity is settled, by matching ``sidecar.sigma_rule_id`` to the rule's ``id``.

    A rule no sidecar claims keeps its provisional filename-derived identifier and
    is reported, so it still appears in listings instead of vanishing from the run.

    Returns:
        The rebound rules and any findings raised while binding them.
    """
    indexed = metadata.by_rule_id()
    findings: list[ValidationFinding] = []
    claimed: dict[str, str] = {}
    result: list[Rule] = []

    for rule in rules:
        key = rule.rule_id.strip().lower()
        if not key:
            findings.append(
                _finding(
                    "SDEL-MET-011",
                    Severity.CRITICAL,
                    rule.relative_path,
                    "rule has no 'id', so no sidecar can claim it and it cannot be "
                    "assigned a catalog identifier",
                    path=rule.relative_path,
                    gate="required_metadata",
                    remediation="Add a stable UUID under 'id' and reference it from a sidecar.",
                )
            )
            result.append(rule)
            continue

        sidecar = indexed.get(key)
        if sidecar is None:
            # The missing sidecar itself is reported once by validate_metadata; here
            # the rule simply keeps its provisional filename-derived identifier.
            result.append(rule)
            continue

        previous = claimed.get(sidecar.catalog_id)
        if previous is not None:
            findings.append(
                _finding(
                    "SDEL-MET-013",
                    Severity.CRITICAL,
                    sidecar.catalog_id,
                    f"catalog_id {sidecar.catalog_id!r} would be assigned to both "
                    f"{previous!r} and {rule.relative_path!r}",
                    path=sidecar.relative_path,
                    gate="unique_catalog_id",
                )
            )
        claimed[sidecar.catalog_id] = rule.relative_path
        result.append(replace(rule, catalog_id=sidecar.catalog_id))

    result.sort(key=lambda item: item.catalog_id)
    return result, findings


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
        category=FindingCategory.METADATA,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        gate=gate,
        remediation=remediation,
    )


def validate_metadata(
    metadata: MetadataSet,
    catalog: RuleCatalog,
    *,
    config: LabConfig,
) -> list[ValidationFinding]:
    """Cross-check sidecars against the catalog.

    Reports missing sidecars, orphan sidecars, identifier mismatches, maturity
    outside the configured range, and hypotheses too thin to review.
    """
    findings: list[ValidationFinding] = []
    indexed = metadata.by_catalog_id()

    for relative, message in metadata.failures:
        findings.append(
            _finding(
                "SDEL-MET-001",
                Severity.CRITICAL,
                relative,
                f"sidecar could not be loaded: {message}",
                path=relative,
                gate="required_metadata",
            )
        )

    for rule in catalog:
        sidecar = indexed.get(rule.catalog_id)
        if sidecar is None:
            findings.append(
                _finding(
                    "SDEL-MET-002",
                    Severity.HIGH,
                    rule.catalog_id,
                    f"no sidecar declares sigma_rule_id {rule.rule_id!r}, so this rule has "
                    "no catalog identifier and is running under a provisional one derived "
                    "from its filename",
                    path=rule.relative_path,
                    gate="sidecar_exists",
                    remediation=(
                        "Create metadata/rules/<catalog_id>.json with sigma_rule_id set to "
                        "this rule's UUID, plus the detection hypothesis, telemetry "
                        "requirements, and ATT&CK mapping."
                    ),
                )
            )
            continue

        if rule.rule_id and sidecar.rule_id.strip().lower() != rule.rule_id.strip().lower():
            findings.append(
                _finding(
                    "SDEL-MET-003",
                    Severity.CRITICAL,
                    rule.catalog_id,
                    f"sidecar rule_id {sidecar.rule_id!r} does not match the rule UUID "
                    f"{rule.rule_id!r}",
                    path=sidecar.relative_path,
                    gate="required_metadata",
                )
            )

        if sidecar.path.stem != rule.catalog_id:
            findings.append(
                _finding(
                    "SDEL-MET-004",
                    Severity.MEDIUM,
                    rule.catalog_id,
                    f"sidecar filename {sidecar.path.name!r} does not match its catalog_id",
                    path=sidecar.relative_path,
                    gate="required_metadata",
                )
            )

        if sidecar.maturity not in config.allowed_maturity:
            severity = (
                Severity.CRITICAL
                if sidecar.maturity in EVIDENCE_UNSUPPORTED_MATURITY
                else Severity.HIGH
            )
            allowed = ", ".join(sorted(str(item) for item in config.allowed_maturity))
            reason = (
                "this maturity claims evidence from real telemetry, which this project "
                "never handles"
                if sidecar.maturity in EVIDENCE_UNSUPPORTED_MATURITY
                else "it is outside the configured range"
            )
            findings.append(
                _finding(
                    "SDEL-MET-005",
                    severity,
                    rule.catalog_id,
                    f"maturity {sidecar.maturity} is not permitted because {reason}; "
                    f"allowed: {allowed}",
                    path=sidecar.relative_path,
                    gate="maturity_allowed",
                )
            )

        if not sidecar.detection_hypothesis:
            findings.append(
                _finding(
                    "SDEL-MET-006",
                    Severity.HIGH,
                    rule.catalog_id,
                    "sidecar has no detection hypothesis",
                    path=sidecar.relative_path,
                    gate="detection_hypothesis_exists",
                    remediation=(
                        "State the adversary behaviour the rule assumes and why the chosen "
                        "telemetry reveals it."
                    ),
                )
            )
        elif len(sidecar.detection_hypothesis) < MIN_HYPOTHESIS_LENGTH:
            findings.append(
                _finding(
                    "SDEL-MET-007",
                    Severity.MEDIUM,
                    rule.catalog_id,
                    f"detection hypothesis is only {len(sidecar.detection_hypothesis)} "
                    f"characters; at least {MIN_HYPOTHESIS_LENGTH} are expected",
                    path=sidecar.relative_path,
                    gate="detection_hypothesis_exists",
                )
            )

        if not sidecar.telemetry_requirements:
            findings.append(
                _finding(
                    "SDEL-MET-008",
                    Severity.HIGH,
                    rule.catalog_id,
                    "sidecar declares no telemetry requirements",
                    path=sidecar.relative_path,
                    gate="telemetry_requirements_exist",
                    remediation=(
                        "List the log sources and fields the rule needs, so a reader can "
                        "tell whether their environment can run it."
                    ),
                )
            )

        if not sidecar.synthetic_only:
            findings.append(
                _finding(
                    "SDEL-MET-009",
                    Severity.CRITICAL,
                    rule.catalog_id,
                    "sidecar sets synthetic_only to false; this project validates against "
                    "generated telemetry exclusively",
                    path=sidecar.relative_path,
                    gate="synthetic_marker_required",
                )
            )

    for sidecar in metadata.sidecars:
        if not CATALOG_ID_PATTERN.match(sidecar.catalog_id):
            findings.append(
                _finding(
                    "SDEL-MET-011",
                    Severity.MEDIUM,
                    sidecar.catalog_id,
                    f"catalog_id {sidecar.catalog_id!r} does not match the project pattern "
                    f"{CATALOG_ID_PATTERN.pattern}",
                    path=sidecar.relative_path,
                    gate="unique_catalog_id",
                )
            )
        if catalog.get(sidecar.catalog_id) is None:
            findings.append(
                _finding(
                    "SDEL-MET-010",
                    Severity.MEDIUM,
                    sidecar.catalog_id,
                    f"sidecar references catalog_id {sidecar.catalog_id!r}, which has no rule",
                    path=sidecar.relative_path,
                    gate="required_metadata",
                    remediation="Delete the orphan sidecar or restore the rule it describes.",
                )
            )

    return findings


def maturity_distribution(metadata: MetadataSet) -> dict[str, int]:
    """Count sidecars per maturity level, for coverage reporting."""
    counts: dict[str, int] = {str(level): 0 for level in Maturity}
    for sidecar in metadata.sidecars:
        counts[str(sidecar.maturity)] += 1
    return {key: value for key, value in counts.items() if value}


__all__ = [
    "CATALOG_ID_PATTERN",
    "KNOWN_SIDECAR_KEYS",
    "MIN_HYPOTHESIS_LENGTH",
    "SIDECAR_GLOBS",
    "MetadataSet",
    "assign_catalog_ids",
    "build_sidecar",
    "load_metadata",
    "load_sidecar_file",
    "maturity_distribution",
    "validate_metadata",
]
