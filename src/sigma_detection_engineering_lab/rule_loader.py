"""Loading Sigma rule files into :class:`~models.Rule` objects.

Loading is a two-stage process. The hardened YAML loader parses the file under
strict structural limits, producing plain Python data. pySigma is then asked to
parse the same text so the rule is validated against the official implementation
rather than only this project's opinion of the specification.

pySigma is an optional import at runtime. When it is absent the loader still
works and reports the fact explicitly; nothing pretends the upstream parse
succeeded.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import (
    PathSafetyError,
    RuleLoadError,
    YamlSafetyError,
)
from sigma_detection_engineering_lab.models import LogSource, Rule, normalise_date
from sigma_detection_engineering_lab.paths import (
    iter_files,
    relative_display,
    safe_read_text,
)
from sigma_detection_engineering_lab.severities import UnknownSeverityError, parse_severity
from sigma_detection_engineering_lab.statuses import UnknownStatusError, parse_status
from sigma_detection_engineering_lab.yaml_loader import load_mapping_documents

RULE_FILENAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:[_-][a-z0-9]+)*\.yml$")
"""Rule filenames are lowercase, ``_`` or ``-`` separated, and end in ``.yml``."""

RULE_GLOBS: Final[tuple[str, ...]] = ("*.yml", "*.yaml")

CORRELATION_KEY: Final[str] = "correlation"
DETECTION_KEY: Final[str] = "detection"

KNOWN_RULE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "title",
        "id",
        "name",
        "related",
        "status",
        "description",
        "references",
        "author",
        "date",
        "modified",
        "tags",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "license",
        "correlation",
        "scope",
    }
)


# --------------------------------------------------------------------------- #
# Optional pySigma integration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PySigmaStatus:
    """Whether pySigma is importable, and which version answered."""

    available: bool
    version: str | None = None
    error: str | None = None


@lru_cache(maxsize=1)
def pysigma_status() -> PySigmaStatus:
    """Report whether pySigma can be imported, caching the answer.

    The import is attempted once per process. A missing backend is a normal,
    reportable condition rather than a crash, so the laboratory remains usable
    for YAML-level work in a minimal environment.
    """
    try:
        from sigma.collection import SigmaCollection  # noqa: F401
        from sigma.rule import SigmaRule  # noqa: F401
    except ImportError as exc:
        return PySigmaStatus(available=False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - a broken install must not abort the run
        return PySigmaStatus(available=False, error=f"unexpected pySigma import failure: {exc}")

    version: str | None
    try:
        from importlib.metadata import version as package_version

        version = package_version("pysigma")
    except Exception:  # noqa: BLE001 - version metadata is informational only
        version = None
    return PySigmaStatus(available=True, version=version)


@dataclass(frozen=True)
class PySigmaParse:
    """Result of asking pySigma to parse a rule file."""

    attempted: bool
    succeeded: bool
    rule_count: int = 0
    errors: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "rule_count": self.rule_count,
            "errors": list(self.errors),
            "detail": self.detail,
        }


def parse_with_pysigma(text: str, *, source: str = "<rule>") -> PySigmaParse:
    """Parse rule text with pySigma's :class:`SigmaCollection`.

    Returns a result object rather than raising, so a single unparseable rule is
    reported as a finding and the rest of the catalog still loads.
    """
    status = pysigma_status()
    if not status.available:
        return PySigmaParse(
            attempted=False,
            succeeded=False,
            detail=(
                "pySigma is not installed; upstream specification parsing was not performed. "
                f"Install the pinned dependencies to enable it ({status.error})"
            ),
        )

    from sigma.collection import SigmaCollection

    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:  # noqa: BLE001 - pySigma raises a wide exception family
        return PySigmaParse(
            attempted=True,
            succeeded=False,
            errors=(f"{type(exc).__name__}: {exc}",),
            detail=f"{source}: pySigma rejected the rule",
        )

    errors: list[str] = []
    rules = list(getattr(collection, "rules", []))
    for rule in rules:
        for error in getattr(rule, "errors", []) or []:
            errors.append(f"{type(error).__name__}: {error}")

    return PySigmaParse(
        attempted=True,
        succeeded=not errors,
        rule_count=len(rules),
        errors=tuple(errors),
        detail=f"{source}: pySigma parsed {len(rules)} rule(s)",
    )


# --------------------------------------------------------------------------- #
# Rule construction
# --------------------------------------------------------------------------- #


def derive_catalog_id(path: Path) -> str:
    """Derive the catalog identifier from a rule filename.

    The stem is used verbatim, which keeps the identifier greppable and makes the
    filename convention meaningful rather than decorative.
    """
    return path.stem


def is_valid_rule_filename(path: Path) -> bool:
    """Return whether the filename follows the project convention."""
    return bool(RULE_FILENAME_PATTERN.match(path.name))


def _string_list(value: object, source: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        result: list[str] = []
        for index, item in enumerate(value):
            if isinstance(item, Mapping):
                raise RuleLoadError(f"{source}: '{key}[{index}]' must be a scalar, not a mapping")
            result.append(str(item))
        return tuple(result)
    return (str(value),)


def _require_str(data: Mapping[str, Any], key: str, source: str) -> str:
    value = data.get(key)
    if value is None:
        raise RuleLoadError(f"{source}: '{key}' is required")
    if not isinstance(value, str) or not value.strip():
        raise RuleLoadError(f"{source}: '{key}' must be a non-empty string")
    return value.strip()


def _split_documents(
    documents: Sequence[Mapping[str, Any]],
    source: str,
) -> tuple[Mapping[str, Any], tuple[Mapping[str, Any], ...]]:
    """Separate the primary rule document from any supporting base rules.

    A correlation file holds one or more base rule documents plus the correlation
    document. The correlation document is the primary rule, since it carries the
    identity the catalog tracks.
    """
    if not documents:
        raise RuleLoadError(f"{source}: file contains no YAML documents")

    correlation_docs = [document for document in documents if CORRELATION_KEY in document]
    if len(correlation_docs) > 1:
        raise RuleLoadError(
            f"{source}: file contains {len(correlation_docs)} correlation documents; "
            "exactly one is supported per file"
        )
    if correlation_docs:
        primary = correlation_docs[0]
        supporting = tuple(document for document in documents if document is not primary)
        return primary, supporting

    if len(documents) > 1:
        raise RuleLoadError(
            f"{source}: file contains {len(documents)} documents but no correlation document; "
            "multi-document files are only supported for correlation rules"
        )
    return documents[0], ()


def build_rule(
    documents: Sequence[Mapping[str, Any]],
    *,
    path: Path,
    relative_path: str,
    raw_text: str = "",
) -> Rule:
    """Build a :class:`Rule` from already-loaded YAML documents.

    Raises:
        RuleLoadError: if the primary document is structurally invalid.
    """
    source = relative_path or path.as_posix()
    primary, _supporting = _split_documents(documents, source)

    unknown = sorted(set(primary) - KNOWN_RULE_KEYS)
    if unknown:
        raise RuleLoadError(
            f"{source}: unknown top-level key(s): {', '.join(unknown)}; "
            f"recognised keys are: {', '.join(sorted(KNOWN_RULE_KEYS))}"
        )

    title = _require_str(primary, "title", source)
    rule_id = str(primary.get("id", "")).strip()

    is_correlation = CORRELATION_KEY in primary
    correlation = primary.get(CORRELATION_KEY) if is_correlation else None
    if is_correlation and not isinstance(correlation, Mapping):
        raise RuleLoadError(f"{source}: 'correlation' must be a mapping")

    detection = primary.get(DETECTION_KEY)
    if detection is None and not is_correlation:
        raise RuleLoadError(f"{source}: 'detection' is required for a non-correlation rule")
    if detection is not None and not isinstance(detection, Mapping):
        raise RuleLoadError(f"{source}: 'detection' must be a mapping")

    try:
        status = parse_status(primary.get("status", "experimental"))
    except UnknownStatusError as exc:
        raise RuleLoadError(f"{source}: {exc}") from exc

    try:
        level = parse_severity(primary.get("level", "medium"))
    except UnknownSeverityError as exc:
        raise RuleLoadError(f"{source}: {exc}") from exc

    logsource_raw = primary.get("logsource")
    if logsource_raw is not None and not isinstance(logsource_raw, Mapping):
        raise RuleLoadError(f"{source}: 'logsource' must be a mapping")

    related_raw = primary.get("related", ())
    related: tuple[Mapping[str, Any], ...]
    if related_raw in (None, ()):
        related = ()
    elif isinstance(related_raw, Sequence) and not isinstance(related_raw, str):
        for entry in related_raw:
            if not isinstance(entry, Mapping):
                raise RuleLoadError(f"{source}: each 'related' entry must be a mapping")
        related = tuple(dict(entry) for entry in related_raw)
    else:
        raise RuleLoadError(f"{source}: 'related' must be a list of mappings")

    return Rule(
        catalog_id=derive_catalog_id(path),
        rule_id=rule_id,
        title=title,
        path=path,
        relative_path=relative_path,
        description=str(primary.get("description", "") or "").strip(),
        status=status,
        level=level,
        author=str(primary.get("author", "") or "").strip(),
        license=(str(primary["license"]).strip() if primary.get("license") else None),
        date=normalise_date(primary.get("date")),
        modified=normalise_date(primary.get("modified")),
        name=(str(primary["name"]).strip() if primary.get("name") else None),
        references=_string_list(primary.get("references"), source, "references"),
        tags=_string_list(primary.get("tags"), source, "tags"),
        falsepositives=_string_list(primary.get("falsepositives"), source, "falsepositives"),
        fields=_string_list(primary.get("fields"), source, "fields"),
        logsource=LogSource.from_mapping(logsource_raw),
        detection=dict(detection) if detection else {},
        related=related,
        is_correlation=is_correlation,
        correlation=dict(correlation) if isinstance(correlation, Mapping) else None,
        documents=tuple(dict(document) for document in documents),
        raw=dict(primary),
        raw_text=raw_text,
    )


def load_rule_file(path: Path, *, config: LabConfig) -> Rule:
    """Load a single Sigma rule file.

    Raises:
        RuleLoadError: if the file cannot be read, parsed, or interpreted.
    """
    relative = relative_display(config.root, path)
    try:
        text = safe_read_text(path, max_bytes=config.limits.max_file_bytes)
    except PathSafetyError as exc:
        raise RuleLoadError(f"{relative}: {exc}") from exc

    try:
        documents = load_mapping_documents(
            text, limits=config.limits.yaml_limits(), source=relative
        )
    except YamlSafetyError as exc:
        raise RuleLoadError(str(exc)) from exc

    return build_rule(documents, path=path, relative_path=relative, raw_text=text)


def discover_rule_files(config: LabConfig, *, directory: Path | None = None) -> list[Path]:
    """Return every candidate rule file under the configured rules directory."""
    target = directory if directory is not None else config.rules_dir
    return list(
        iter_files(
            config.root,
            target,
            RULE_GLOBS,
            allow_symlinks=config.limits.allow_symlinks,
            max_path_length=config.limits.max_path_length,
        )
    )


@dataclass(frozen=True)
class LoadOutcome:
    """Result of loading a whole directory of rules."""

    rules: tuple[Rule, ...] = ()
    failures: tuple[tuple[str, str], ...] = ()
    """Pairs of ``(relative path, error message)`` for files that failed to load."""

    @property
    def loaded_count(self) -> int:
        return len(self.rules)

    @property
    def failure_count(self) -> int:
        return len(self.failures)


def load_rules(config: LabConfig, *, directory: Path | None = None) -> LoadOutcome:
    """Load every rule under the configured directory, collecting failures.

    One malformed rule does not prevent the rest of the catalog from loading;
    each failure is returned so the caller can turn it into a finding.
    """
    rules: list[Rule] = []
    failures: list[tuple[str, str]] = []
    for path in discover_rule_files(config, directory=directory):
        relative = relative_display(config.root, path)
        try:
            rules.append(load_rule_file(path, config=config))
        except RuleLoadError as exc:
            failures.append((relative, str(exc)))
    rules.sort(key=lambda rule: rule.catalog_id)
    return LoadOutcome(rules=tuple(rules), failures=tuple(failures))


def correlation_base_documents(rule: Rule) -> dict[str, Mapping[str, Any]]:
    """Return the base rule documents shipped inside a correlation rule file.

    Keyed by every identifier a correlation ``rules:`` entry may use: the ``name``
    field and the ``id`` field.
    """
    resolved: dict[str, Mapping[str, Any]] = {}
    if not rule.is_correlation:
        return resolved
    for document in rule.documents:
        if CORRELATION_KEY in document or DETECTION_KEY not in document:
            continue
        for key in ("name", "id"):
            value = document.get(key)
            if isinstance(value, str) and value.strip():
                resolved[value.strip()] = document
    return resolved


__all__ = [
    "CORRELATION_KEY",
    "DETECTION_KEY",
    "KNOWN_RULE_KEYS",
    "RULE_FILENAME_PATTERN",
    "RULE_GLOBS",
    "LoadOutcome",
    "PySigmaParse",
    "PySigmaStatus",
    "build_rule",
    "correlation_base_documents",
    "derive_catalog_id",
    "discover_rule_files",
    "is_valid_rule_filename",
    "load_rule_file",
    "load_rules",
    "parse_with_pysigma",
    "pysigma_status",
]
