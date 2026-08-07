"""The telemetry catalog: what a rule needs before it can work anywhere.

A detection is only as good as the data feeding it. Each sidecar declares the
telemetry its rule depends on, and this module checks those declarations against
a catalog of known sources at ``config/telemetry-catalog.json``. That catches two
failure modes a reader would otherwise hit only in production: a rule requiring
telemetry nobody has described, and a rule matching on fields its declared
telemetry does not carry.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig, read_config_json
from sigma_detection_engineering_lab.errors import ConfigError, TelemetryError
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    FindingCategory,
    Rule,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

CATALOG_FILENAME: Final[str] = "telemetry-catalog.json"

TELEMETRY_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:[_-][a-z0-9]+)*$")


@dataclass(frozen=True)
class TelemetrySource:
    """One log source the laboratory knows how to describe."""

    telemetry_id: str
    name: str = ""
    product: str | None = None
    category: str | None = None
    service: str | None = None
    platform: str | None = None
    fields: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    required_logs: tuple[str, ...] = ()
    description: str = ""
    notes: str | None = None

    def has_field(self, name: str) -> bool:
        """Return whether this source is documented as carrying ``name``."""
        lowered = name.strip().lower()
        return any(item.strip().lower() == lowered for item in self.fields)

    def has_channel(self, name: str) -> bool:
        """Return whether this source is documented as delivered on ``name``."""
        lowered = name.strip().lower()
        return any(item.strip().lower() == lowered for item in self.channels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_id": self.telemetry_id,
            "name": self.name,
            "product": self.product,
            "category": self.category,
            "service": self.service,
            "platform": self.platform,
            "fields": list(self.fields),
            "channels": list(self.channels),
            "providers": list(self.providers),
            "required_logs": list(self.required_logs),
            "description": self.description,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class TelemetryCatalog:
    """The loaded telemetry catalog, indexed by identifier."""

    sources: Mapping[str, TelemetrySource] = field(default_factory=dict)
    schema_version: str = ""
    available: bool = False
    load_error: str | None = None

    def get(self, telemetry_id: str) -> TelemetrySource | None:
        return self.sources.get(telemetry_id.strip().lower())

    def resolve(self, reference: str) -> TelemetrySource | None:
        """Resolve a profile identifier or a declared log name to a source.

        Sidecars name the telemetry they need in prose ("Windows Security event
        log") because that is what a reader of the sidecar needs to see. The
        catalog lists the same string under ``required_logs``, which makes it a
        usable join key without asking authors to memorise profile identifiers.
        """
        direct = self.get(reference)
        if direct is not None:
            return direct
        needle = reference.strip().lower()
        for source in self.sources.values():
            if any(item.strip().lower() == needle for item in source.required_logs):
                return source
        return None

    def for_logsource(
        self,
        product: str | None,
        category: str | None,
        service: str | None = None,
    ) -> tuple[TelemetrySource, ...]:
        """Return sources compatible with a Sigma logsource selector."""

        def part_matches(required: str | None, actual: str | None) -> bool:
            if required is None:
                return True
            if actual is None:
                return False
            return required.strip().lower() == actual.strip().lower()

        return tuple(
            source
            for source in self.sources.values()
            if part_matches(product, source.product)
            and part_matches(category, source.category)
            and part_matches(service, source.service)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "schema_version": self.schema_version,
            "source_count": len(self.sources),
            "load_error": self.load_error,
            "sources": [source.to_dict() for source in self.sources.values()],
        }


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    raise TelemetryError(f"{label}: expected a string or a list of strings")


def build_catalog(data: Mapping[str, Any], *, label: str = CATALOG_FILENAME) -> TelemetryCatalog:
    """Build a telemetry catalog from a decoded JSON document.

    Raises:
        TelemetryError: if the document is structurally invalid.
    """
    entries = _catalog_entries(data, label)

    sources: dict[str, TelemetrySource] = {}
    for entry_label, telemetry_id, entry in entries:
        key = telemetry_id.strip().lower()
        if not TELEMETRY_ID_PATTERN.match(key):
            raise TelemetryError(
                f"{entry_label}: telemetry_id {telemetry_id!r} must be lowercase words "
                "separated by hyphens or underscores"
            )
        if key in sources:
            raise TelemetryError(f"{entry_label}: duplicate telemetry_id {telemetry_id!r}")

        logsource = entry.get("logsource", {})
        if not isinstance(logsource, Mapping):
            raise TelemetryError(f"{entry_label}: 'logsource' must be an object")

        sources[key] = TelemetrySource(
            telemetry_id=key,
            name=str(entry.get("name", "") or key),
            product=_logsource_part(entry, logsource, "product"),
            category=_logsource_part(entry, logsource, "category"),
            service=_logsource_part(entry, logsource, "service"),
            platform=_optional(entry, "platform"),
            fields=_string_tuple(
                entry.get("fields", entry.get("optional_fields")), f"{entry_label}.fields"
            ),
            channels=_string_tuple(entry.get("channels"), f"{entry_label}.channels"),
            providers=_string_tuple(entry.get("providers"), f"{entry_label}.providers"),
            required_logs=_string_tuple(entry.get("required_logs"), f"{entry_label}.required_logs"),
            description=str(entry.get("description", "") or ""),
            notes=_optional(entry, "notes"),
        )

    return TelemetryCatalog(
        sources=sources,
        schema_version=str(data.get("schema_version", "")),
        available=True,
    )


def _logsource_part(
    entry: Mapping[str, Any],
    logsource: Mapping[str, Any],
    name: str,
) -> str | None:
    """Read a logsource component, whether written inline or nested."""
    return _optional(entry, name) or _optional(logsource, name)


def _catalog_entries(
    data: Mapping[str, Any],
    label: str,
) -> list[tuple[str, str, Mapping[str, Any]]]:
    """Normalise the two accepted catalog shapes into labelled entries.

    ``profiles`` is an object keyed by identifier, which keeps the file readable
    when each entry is long. ``sources`` is a list of objects carrying their own
    identifier. Both are accepted so the catalog format is not a breaking detail.
    """
    profiles = data.get("profiles")
    if profiles is not None:
        if not isinstance(profiles, Mapping):
            raise TelemetryError(f"{label}: 'profiles' must be an object")
        entries: list[tuple[str, str, Mapping[str, Any]]] = []
        for telemetry_id, entry in profiles.items():
            entry_label = f"{label}.profiles.{telemetry_id}"
            if not isinstance(entry, Mapping):
                raise TelemetryError(f"{entry_label}: must be an object")
            entries.append((entry_label, str(telemetry_id), entry))
        return entries

    raw_sources = data.get("sources")
    if raw_sources is None:
        raise TelemetryError(f"{label}: either 'profiles' or 'sources' is required")
    if not isinstance(raw_sources, Sequence) or isinstance(raw_sources, str):
        raise TelemetryError(f"{label}: 'sources' must be a list")

    entries = []
    for index, entry in enumerate(raw_sources):
        entry_label = f"{label}.sources[{index}]"
        if not isinstance(entry, Mapping):
            raise TelemetryError(f"{entry_label}: must be an object")
        telemetry_id = entry.get("telemetry_id") or entry.get("id")
        if not isinstance(telemetry_id, str) or not telemetry_id.strip():
            raise TelemetryError(f"{entry_label}: 'telemetry_id' is required")
        entries.append((entry_label, telemetry_id, entry))
    return entries


def _optional(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return str(value).strip() if isinstance(value, str) and value.strip() else None


def load_telemetry_catalog(config: LabConfig) -> TelemetryCatalog:
    """Load ``config/telemetry-catalog.json``.

    An absent catalog produces an unavailable result rather than an error; the
    validators then report that telemetry declarations could not be verified.
    """
    try:
        data = read_config_json(config, CATALOG_FILENAME)
    except ConfigError as exc:
        return TelemetryCatalog(available=False, load_error=str(exc))
    try:
        return build_catalog(data)
    except TelemetryError as exc:
        return TelemetryCatalog(available=False, load_error=str(exc))


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
        category=FindingCategory.TELEMETRY,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        gate=gate,
        remediation=remediation,
    )


def detection_field_names(rule: Rule) -> tuple[str, ...]:
    """Return every event field a rule's detection reads.

    Modifier suffixes are stripped, so ``Image|endswith`` reports as ``Image``.
    """
    names: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                if isinstance(key, str):
                    base = key.split("|", 1)[0].strip()
                    if base and base not in names:
                        names.append(base)
                visit(value)
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            for item in node:
                visit(item)

    for key, value in rule.detection.items():
        if key == "condition":
            continue
        visit(value)
    return tuple(names)


def validate_requirements(
    rule: Rule,
    telemetry_ids: Iterable[str],
    *,
    catalog: TelemetryCatalog,
    path: str | None,
    declared_fields: Sequence[str] = (),
    declared_channels: Sequence[str] = (),
) -> list[ValidationFinding]:
    """Check one rule's declared telemetry against the catalog.

    Args:
        rule: The rule whose sidecar made the declaration.
        telemetry_ids: Profile identifiers or declared log names from the sidecar.
        catalog: The loaded telemetry catalog.
        path: Sidecar path, used to point findings at the file to edit.
        declared_fields: Fields the sidecar itself says the rule needs. These count
            as documented, since the sidecar is the record of intent; the check
            catches detections reading fields nobody declared at all.
        declared_channels: Channels the sidecar says the telemetry arrives on.
    """
    findings: list[ValidationFinding] = []
    resolved: list[TelemetrySource] = []

    for telemetry_id in telemetry_ids:
        text = telemetry_id.strip()
        if not text:
            findings.append(
                _finding(
                    "SDEL-TEL-001",
                    Severity.MEDIUM,
                    rule.catalog_id,
                    "empty telemetry identifier in the sidecar",
                    path=path,
                    gate="telemetry_requirements_exist",
                )
            )
            continue
        if not catalog.available:
            findings.append(
                _finding(
                    "SDEL-TEL-002",
                    Severity.MEDIUM,
                    rule.catalog_id,
                    f"telemetry {text!r} could not be verified: no telemetry catalog is "
                    f"available ({catalog.load_error or 'file not found'})",
                    path=path,
                    gate="telemetry_requirements_exist",
                    remediation=f"Add config/{CATALOG_FILENAME} describing the known sources.",
                )
            )
            continue
        source = catalog.resolve(text)
        if source is None:
            findings.append(
                _finding(
                    "SDEL-TEL-003",
                    Severity.HIGH,
                    rule.catalog_id,
                    f"telemetry {text!r} is not defined in the telemetry catalog",
                    path=path,
                    gate="telemetry_requirements_exist",
                    remediation=(
                        f"Add the source to config/{CATALOG_FILENAME}, or reference an "
                        "existing telemetry identifier or required log name."
                    ),
                )
            )
            continue
        resolved.append(source)

    if resolved:
        findings.extend(_validate_channels(rule, resolved, declared_channels, path=path))
    if resolved and not rule.is_correlation:
        findings.extend(_validate_field_availability(rule, resolved, declared_fields, path=path))
        findings.extend(_validate_logsource_agreement(rule, resolved, path=path))
    return findings


def _validate_channels(
    rule: Rule,
    sources: Sequence[TelemetrySource],
    declared_channels: Sequence[str],
    *,
    path: str | None,
) -> list[ValidationFinding]:
    """Flag a sidecar channel the resolved telemetry does not deliver."""
    documented: set[str] = set()
    for source in sources:
        documented.update(item.strip().lower() for item in source.channels)
    if not documented:
        return []

    unknown = sorted(
        {channel for channel in declared_channels if channel.strip().lower() not in documented}
    )
    if not unknown:
        return []
    return [
        _finding(
            "SDEL-TEL-006",
            Severity.LOW,
            rule.catalog_id,
            f"sidecar declares channel(s) the telemetry catalog does not list: "
            f"{', '.join(unknown)}",
            path=path,
            gate="telemetry_requirements_exist",
            remediation=(
                f"Add the channel to the profile in config/{CATALOG_FILENAME} if it really "
                "carries this telemetry."
            ),
        )
    ]


def _validate_field_availability(
    rule: Rule,
    sources: Sequence[TelemetrySource],
    declared_fields: Sequence[str],
    *,
    path: str | None,
) -> list[ValidationFinding]:
    """Flag detection fields neither the sidecar nor the catalog documents."""
    documented: set[str] = {name.strip().lower() for name in declared_fields}
    for source in sources:
        documented.update(item.strip().lower() for item in source.fields)
    if not documented:
        return []

    missing = [name for name in detection_field_names(rule) if name.lower() not in documented]
    if not missing:
        return []
    return [
        _finding(
            "SDEL-TEL-004",
            Severity.MEDIUM,
            rule.catalog_id,
            f"detection reads field(s) not documented by the declared telemetry: "
            f"{', '.join(sorted(missing))}",
            path=path,
            gate="telemetry_requirements_exist",
            remediation=(
                "Add the fields to the telemetry catalog entry, or declare the telemetry "
                "source that actually provides them."
            ),
        )
    ]


def _validate_logsource_agreement(
    rule: Rule,
    sources: Sequence[TelemetrySource],
    *,
    path: str | None,
) -> list[ValidationFinding]:
    """Flag a rule whose logsource matches none of its declared telemetry."""
    if rule.logsource.is_empty:
        return []

    def compatible(source: TelemetrySource) -> bool:
        for required, actual in (
            (rule.logsource.product, source.product),
            (rule.logsource.category, source.category),
        ):
            if required is None:
                continue
            if actual is not None and required.strip().lower() != actual.strip().lower():
                return False
        return True

    if any(compatible(source) for source in sources):
        return []
    declared = ", ".join(source.telemetry_id for source in sources)
    return [
        _finding(
            "SDEL-TEL-005",
            Severity.MEDIUM,
            rule.catalog_id,
            f"rule logsource {rule.logsource.key} does not correspond to any declared "
            f"telemetry ({declared})",
            path=path,
            gate="telemetry_requirements_exist",
        )
    ]


def validate_catalog(
    rules: RuleCatalog,
    metadata: MetadataSet,
    catalog: TelemetryCatalog,
) -> list[ValidationFinding]:
    """Validate telemetry declarations across every rule with a sidecar."""
    findings: list[ValidationFinding] = []
    indexed = metadata.by_catalog_id()
    for rule in rules:
        sidecar = indexed.get(rule.catalog_id)
        if sidecar is None:
            continue
        findings.extend(
            validate_requirements(
                rule,
                [item.telemetry_id for item in sidecar.telemetry_requirements],
                catalog=catalog,
                path=sidecar.relative_path,
                declared_fields=sidecar.declared_fields,
                declared_channels=sidecar.required_channels,
            )
        )
    return findings


def telemetry_usage(metadata: MetadataSet) -> dict[str, int]:
    """Count how many rules depend on each telemetry source."""
    counts: dict[str, int] = {}
    for sidecar in metadata.sidecars:
        for requirement in sidecar.telemetry_requirements:
            key = requirement.telemetry_id.strip().lower()
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "CATALOG_FILENAME",
    "TELEMETRY_ID_PATTERN",
    "TelemetryCatalog",
    "TelemetrySource",
    "build_catalog",
    "detection_field_names",
    "load_telemetry_catalog",
    "telemetry_usage",
    "validate_catalog",
    "validate_requirements",
]
