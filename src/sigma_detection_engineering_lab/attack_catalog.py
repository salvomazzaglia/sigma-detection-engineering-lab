"""The vendored, offline MITRE ATT&CK catalog.

Identifiers are validated against a subset of ATT&CK vendored into
``data/attack/*.json``. Nothing is fetched at runtime, and no identifier is ever
accepted merely because it looks well formed: a syntactically valid ``T9999``
that ATT&CK does not define is an invented identifier and is rejected.

Both file layouts are accepted. A single combined document may carry any of the
object keys, and split files (``techniques.json``, ``tactics.json`` and so on)
are merged, with the filename supplying the object type when the document is a
bare list.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import AttackCatalogError, PathSafetyError
from sigma_detection_engineering_lab.paths import (
    iter_files,
    relative_display,
    safe_read_text,
)

TECHNIQUE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^TA\d{4}$")
TACTIC_SHORTNAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DETECTION_STRATEGY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^DET\d{4}$")
ANALYTIC_PATTERN: Final[re.Pattern[str]] = re.compile(r"^AN\d{4}$")
DATA_COMPONENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^DC\d{4}$")

OBJECT_KEYS: Final[tuple[str, ...]] = (
    "techniques",
    "tactics",
    "detection_strategies",
    "analytics",
    "data_components",
)

_FILENAME_HINTS: Final[dict[str, str]] = {
    "techniques": "techniques",
    "technique": "techniques",
    "tactics": "tactics",
    "tactic": "tactics",
    "detection_strategies": "detection_strategies",
    "detection-strategies": "detection_strategies",
    "analytics": "analytics",
    "data_components": "data_components",
    "data-components": "data_components",
}


@dataclass(frozen=True)
class AttackObject:
    """One ATT&CK object from the vendored subset."""

    object_id: str
    name: str = ""
    object_type: str = ""
    shortname: str | None = None
    tactics: tuple[str, ...] = ()
    deprecated: bool = False
    revoked: bool = False
    url: str | None = None

    @property
    def is_active(self) -> bool:
        """Return whether the object is safe to map to."""
        return not (self.deprecated or self.revoked)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.object_id,
            "name": self.name,
            "type": self.object_type,
            "shortname": self.shortname,
            "tactics": list(self.tactics),
            "deprecated": self.deprecated,
            "revoked": self.revoked,
            "url": self.url,
        }


def _as_bool(value: object) -> bool:
    return bool(value) if isinstance(value, bool) else False


def _build_object(entry: object, object_type: str, source: str) -> AttackObject:
    if isinstance(entry, str):
        return AttackObject(object_id=entry.strip(), object_type=object_type)
    if not isinstance(entry, Mapping):
        raise AttackCatalogError(
            f"{source}: each {object_type} entry must be a string or an object, "
            f"got {type(entry).__name__}"
        )
    object_id = entry.get("id") or entry.get("attack_id") or entry.get("external_id")
    if not isinstance(object_id, str) or not object_id.strip():
        raise AttackCatalogError(f"{source}: {object_type} entry has no 'id'")

    tactics_raw = entry.get("tactics") or entry.get("kill_chain_phases") or ()
    tactics: list[str] = []
    if isinstance(tactics_raw, str):
        tactics = [tactics_raw]
    elif isinstance(tactics_raw, Sequence):
        for item in tactics_raw:
            if isinstance(item, str):
                tactics.append(item)
            elif isinstance(item, Mapping):
                phase = item.get("phase_name") or item.get("shortname")
                if isinstance(phase, str):
                    tactics.append(phase)

    shortname = entry.get("shortname") or entry.get("x_mitre_shortname")
    return AttackObject(
        object_id=object_id.strip(),
        name=str(entry.get("name", "") or ""),
        object_type=object_type,
        shortname=str(shortname).strip() if isinstance(shortname, str) else None,
        tactics=tuple(tactics),
        deprecated=_as_bool(entry.get("deprecated") or entry.get("x_mitre_deprecated")),
        revoked=_as_bool(entry.get("revoked")),
        url=str(entry["url"]) if isinstance(entry.get("url"), str) else None,
    )


@dataclass(frozen=True)
class AttackCatalog:
    """The merged, indexed ATT&CK subset."""

    techniques: Mapping[str, AttackObject] = field(default_factory=dict)
    tactics: Mapping[str, AttackObject] = field(default_factory=dict)
    detection_strategies: Mapping[str, AttackObject] = field(default_factory=dict)
    analytics: Mapping[str, AttackObject] = field(default_factory=dict)
    data_components: Mapping[str, AttackObject] = field(default_factory=dict)
    attack_version: str | None = None
    domain: str = "enterprise-attack"
    sources: tuple[str, ...] = ()
    load_errors: tuple[tuple[str, str], ...] = ()

    @property
    def is_available(self) -> bool:
        """Return whether any objects were loaded at all."""
        return bool(self.techniques or self.tactics or self.detection_strategies)

    @property
    def object_count(self) -> int:
        return sum(len(getattr(self, key)) for key in OBJECT_KEYS)

    def collection(self, object_type: str) -> Mapping[str, AttackObject]:
        """Return the index for one object type.

        Raises:
            AttackCatalogError: if the type is unknown.
        """
        if object_type not in OBJECT_KEYS:
            raise AttackCatalogError(
                f"unknown ATT&CK object type {object_type!r}; expected one of: "
                f"{', '.join(OBJECT_KEYS)}"
            )
        result: Mapping[str, AttackObject] = getattr(self, object_type)
        return result

    def get_technique(self, technique_id: str) -> AttackObject | None:
        return self.techniques.get(technique_id.strip().upper())

    def get_tactic(self, identifier: str) -> AttackObject | None:
        """Look up a tactic by ``TA####`` identifier or by shortname."""
        needle = identifier.strip()
        found = self.tactics.get(needle.upper())
        if found is not None:
            return found
        lowered = needle.lower()
        for tactic in self.tactics.values():
            if tactic.shortname and tactic.shortname.lower() == lowered:
                return tactic
            if tactic.name and tactic.name.lower().replace(" ", "-") == lowered:
                return tactic
        return None

    def get(self, object_type: str, identifier: str) -> AttackObject | None:
        """Look up any object by type and identifier."""
        if object_type == "tactics":
            return self.get_tactic(identifier)
        return self.collection(object_type).get(identifier.strip().upper())

    def parent_technique(self, technique_id: str) -> str:
        """Return the parent technique identifier of a sub-technique."""
        return technique_id.split(".", 1)[0].strip().upper()

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.is_available,
            "attack_version": self.attack_version,
            "domain": self.domain,
            "object_count": self.object_count,
            "counts": {key: len(getattr(self, key)) for key in OBJECT_KEYS},
            "sources": list(self.sources),
            "load_errors": [
                {"path": path, "message": message} for path, message in self.load_errors
            ],
        }


def _infer_type_from_filename(path: Path) -> str | None:
    stem = path.stem.lower().replace(" ", "_")
    return _FILENAME_HINTS.get(stem)


def _merge_document(
    document: Any,
    *,
    path: Path,
    source: str,
    buckets: dict[str, dict[str, AttackObject]],
) -> tuple[str | None, str | None]:
    """Merge one JSON document into the type buckets.

    Returns the ATT&CK version and domain declared by the document, if any.
    """
    if isinstance(document, list):
        inferred = _infer_type_from_filename(path)
        if inferred is None:
            raise AttackCatalogError(
                f"{source}: document is a bare list but the filename does not identify an "
                f"object type; name the file one of: {', '.join(sorted(set(_FILENAME_HINTS)))}"
            )
        for entry in document:
            obj = _build_object(entry, inferred, source)
            buckets[inferred][obj.object_id.upper()] = obj
        return None, None

    if not isinstance(document, Mapping):
        raise AttackCatalogError(f"{source}: document root must be an object or a list")

    for key in OBJECT_KEYS:
        entries = document.get(key)
        if entries is None:
            continue
        if not isinstance(entries, Sequence) or isinstance(entries, str):
            raise AttackCatalogError(f"{source}: '{key}' must be a list")
        for entry in entries:
            obj = _build_object(entry, key, source)
            buckets[key][obj.object_id.upper()] = obj

    version = document.get("attack_version") or document.get("version")
    domain = document.get("domain")
    return (
        str(version) if isinstance(version, (str, int, float)) else None,
        str(domain) if isinstance(domain, str) else None,
    )


def load_attack_catalog(config: LabConfig, *, directory: Path | None = None) -> AttackCatalog:
    """Load and merge every vendored ATT&CK JSON file.

    A missing directory yields an empty, unavailable catalog rather than an
    error, so the rest of the laboratory still runs; mapping validation then
    reports that identifiers could not be verified.
    """
    target = directory if directory is not None else config.attack_data_dir
    buckets: dict[str, dict[str, AttackObject]] = {key: {} for key in OBJECT_KEYS}
    sources: list[str] = []
    errors: list[tuple[str, str]] = []
    attack_version: str | None = None
    domain: str | None = None

    if not target.is_dir():
        return AttackCatalog(
            load_errors=(
                (
                    relative_display(config.root, target),
                    "ATT&CK data directory does not exist; identifiers cannot be verified",
                ),
            )
        )

    for path in iter_files(
        config.root,
        target,
        ("*.json",),
        allow_symlinks=config.limits.allow_symlinks,
        max_path_length=config.limits.max_path_length,
    ):
        source = relative_display(config.root, path)
        try:
            text = safe_read_text(path, max_bytes=config.limits.max_file_bytes)
            document = json.loads(text)
            found_version, found_domain = _merge_document(
                document, path=path, source=source, buckets=buckets
            )
        except (AttackCatalogError, PathSafetyError) as exc:
            errors.append((source, str(exc)))
            continue
        except json.JSONDecodeError as exc:
            errors.append((source, f"invalid JSON: {exc}"))
            continue
        sources.append(source)
        attack_version = attack_version or found_version
        domain = domain or found_domain

    return AttackCatalog(
        techniques=buckets["techniques"],
        tactics=buckets["tactics"],
        detection_strategies=buckets["detection_strategies"],
        analytics=buckets["analytics"],
        data_components=buckets["data_components"],
        attack_version=attack_version,
        domain=domain or "enterprise-attack",
        sources=tuple(sources),
        load_errors=tuple(errors),
    )


def is_well_formed(object_type: str, identifier: str) -> bool:
    """Return whether an identifier has the right shape for its object type.

    Shape is necessary but never sufficient: the identifier must also exist in
    the vendored catalog.
    """
    text = identifier.strip()
    if object_type == "techniques":
        return bool(TECHNIQUE_PATTERN.match(text.upper()))
    if object_type == "tactics":
        return bool(
            TACTIC_ID_PATTERN.match(text.upper()) or TACTIC_SHORTNAME_PATTERN.match(text.lower())
        )
    if object_type == "detection_strategies":
        return bool(DETECTION_STRATEGY_PATTERN.match(text.upper()))
    if object_type == "analytics":
        return bool(ANALYTIC_PATTERN.match(text.upper()))
    if object_type == "data_components":
        return bool(DATA_COMPONENT_PATTERN.match(text.upper()))
    raise AttackCatalogError(f"unknown ATT&CK object type {object_type!r}")


def technique_ids_from_tags(tags: Iterable[str]) -> tuple[str, ...]:
    """Extract technique identifiers from Sigma ``attack.`` tags.

    Sigma writes sub-techniques as ``attack.t1059.001``; the dotted suffix is
    restored to canonical ``T1059.001`` form.
    """
    found: list[str] = []
    for tag in tags:
        text = tag.strip().lower()
        if not text.startswith("attack."):
            continue
        remainder = text[len("attack.") :]
        candidate = remainder.upper()
        if TECHNIQUE_PATTERN.match(candidate) and candidate not in found:
            found.append(candidate)
    return tuple(found)


def tactic_names_from_tags(tags: Iterable[str]) -> tuple[str, ...]:
    """Extract tactic shortnames from Sigma ``attack.`` tags."""
    found: list[str] = []
    for tag in tags:
        text = tag.strip().lower()
        if not text.startswith("attack."):
            continue
        remainder = text[len("attack.") :]
        if TECHNIQUE_PATTERN.match(remainder.upper()):
            continue
        normalised = remainder.replace("_", "-")
        if TACTIC_SHORTNAME_PATTERN.match(normalised) and normalised not in found:
            found.append(normalised)
    return tuple(found)


__all__ = [
    "ANALYTIC_PATTERN",
    "DATA_COMPONENT_PATTERN",
    "DETECTION_STRATEGY_PATTERN",
    "OBJECT_KEYS",
    "TACTIC_ID_PATTERN",
    "TACTIC_SHORTNAME_PATTERN",
    "TECHNIQUE_PATTERN",
    "AttackCatalog",
    "AttackObject",
    "is_well_formed",
    "load_attack_catalog",
    "tactic_names_from_tags",
    "technique_ids_from_tags",
]
