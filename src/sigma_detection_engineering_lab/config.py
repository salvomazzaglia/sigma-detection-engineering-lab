"""Configuration loading with bounds checking.

Configuration lives in ``config/*.json`` at the project root. Because those files
determine the safety limits applied to untrusted rule content, they are validated
rather than trusted: every limit must be present in the right type and inside a
hard-coded range, so a mistaken edit cannot quietly disable a protection.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.constants import (
    PROJECT_LICENSE,
    SYNTHETIC_DATA_BANNER,
)
from sigma_detection_engineering_lab.errors import ConfigError
from sigma_detection_engineering_lab.paths import (
    DEFAULT_MAX_FILE_BYTES,
    find_project_root,
    safe_read_text,
    safe_resolve,
)
from sigma_detection_engineering_lab.statuses import (
    Maturity,
    SigmaStatus,
    UnknownMaturityError,
    UnknownStatusError,
    parse_maturity_set,
    parse_status_set,
)
from sigma_detection_engineering_lab.yaml_loader import YamlLimits

CONFIG_DIRECTORY: Final[str] = "config"
DEFAULT_PROFILE: Final[str] = "default"
CONFIG_MAX_BYTES: Final[int] = 262_144

LIMIT_BOUNDS: Final[dict[str, tuple[int, int]]] = {
    "max_file_bytes": (1_024, 16_777_216),
    "max_yaml_depth": (4, 256),
    "max_yaml_nodes": (64, 200_000),
    "max_yaml_aliases": (0, 64),
    "max_scalar_length": (64, 1_048_576),
    "max_mapping_size": (8, 10_000),
    "max_sequence_length": (8, 10_000),
    "max_path_length": (64, 32_768),
    "max_regex_length": (16, 4_096),
    "max_events_per_fixture": (1, 100_000),
    "max_correlation_sequence_events": (1, 10_000),
}
"""Inclusive ``(minimum, maximum)`` accepted for each integer limit."""

BOOLEAN_LIMITS: Final[tuple[str, ...]] = ("allow_symlinks",)

REQUIRED_PATH_KEYS: Final[tuple[str, ...]] = (
    "rules",
    "metadata",
    "fixtures",
    "attack_data",
    "examples",
    "schemas",
    "temp_output",
)


@dataclass(frozen=True)
class Limits:
    """Validated safety limits shared by every subsystem."""

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_yaml_depth: int = 32
    max_yaml_nodes: int = 5_000
    max_yaml_aliases: int = 0
    max_scalar_length: int = 8_192
    max_mapping_size: int = 512
    max_sequence_length: int = 512
    max_path_length: int = 4_096
    max_regex_length: int = 256
    max_events_per_fixture: int = 200
    max_correlation_sequence_events: int = 100
    allow_symlinks: bool = False

    def yaml_limits(self) -> YamlLimits:
        """Project these limits onto the subset the YAML loader needs."""
        return YamlLimits(
            max_file_bytes=self.max_file_bytes,
            max_depth=self.max_yaml_depth,
            max_nodes=self.max_yaml_nodes,
            max_aliases=self.max_yaml_aliases,
            max_scalar_length=self.max_scalar_length,
            max_mapping_size=self.max_mapping_size,
            max_sequence_length=self.max_sequence_length,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_yaml_depth": self.max_yaml_depth,
            "max_yaml_nodes": self.max_yaml_nodes,
            "max_yaml_aliases": self.max_yaml_aliases,
            "max_scalar_length": self.max_scalar_length,
            "max_mapping_size": self.max_mapping_size,
            "max_sequence_length": self.max_sequence_length,
            "max_path_length": self.max_path_length,
            "max_regex_length": self.max_regex_length,
            "max_events_per_fixture": self.max_events_per_fixture,
            "max_correlation_sequence_events": self.max_correlation_sequence_events,
            "allow_symlinks": self.allow_symlinks,
        }


@dataclass(frozen=True)
class ProjectDirectories:
    """Project-relative directory names taken from the ``paths`` block."""

    rules: str = "rules"
    metadata: str = "metadata/rules"
    fixtures: str = "fixtures"
    attack_data: str = "data/attack"
    examples: str = "examples"
    schemas: str = "schemas"
    temp_output: str = "temp"

    def to_dict(self) -> dict[str, str]:
        return {
            "rules": self.rules,
            "metadata": self.metadata,
            "fixtures": self.fixtures,
            "attack_data": self.attack_data,
            "examples": self.examples,
            "schemas": self.schemas,
            "temp_output": self.temp_output,
        }


@dataclass(frozen=True)
class LabConfig:
    """Fully validated laboratory configuration."""

    root: Path
    source_path: Path
    profile: str
    schema_version: str
    project_name: str
    directories: ProjectDirectories
    limits: Limits
    required_authors: tuple[str, ...]
    license: str
    allowed_sigma_statuses: frozenset[SigmaStatus]
    blocked_sigma_statuses: frozenset[SigmaStatus]
    allowed_maturity: frozenset[Maturity]
    synthetic_hosts: tuple[str, ...] = ()
    synthetic_users: tuple[str, ...] = ()
    synthetic_banner: str = SYNTHETIC_DATA_BANNER
    demo_mode: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)

    def resolve(self, kind: str) -> Path:
        """Return the absolute, contained path for a configured directory.

        Raises:
            ConfigError: if ``kind`` is not a known directory key.
        """
        mapping = self.directories.to_dict()
        if kind not in mapping:
            known = ", ".join(sorted(mapping))
            raise ConfigError(f"unknown directory key {kind!r}; expected one of: {known}")
        return safe_resolve(
            self.root,
            mapping[kind],
            allow_symlinks=self.limits.allow_symlinks,
            max_path_length=self.limits.max_path_length,
        )

    @property
    def rules_dir(self) -> Path:
        return self.resolve("rules")

    @property
    def metadata_dir(self) -> Path:
        return self.resolve("metadata")

    @property
    def fixtures_dir(self) -> Path:
        return self.resolve("fixtures")

    @property
    def attack_data_dir(self) -> Path:
        return self.resolve("attack_data")

    @property
    def schemas_dir(self) -> Path:
        return self.resolve("schemas")

    @property
    def examples_dir(self) -> Path:
        return self.resolve("examples")

    @property
    def temp_dir(self) -> Path:
        return self.resolve("temp_output")

    @property
    def config_dir(self) -> Path:
        return safe_resolve(
            self.root,
            CONFIG_DIRECTORY,
            allow_symlinks=self.limits.allow_symlinks,
            max_path_length=self.limits.max_path_length,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "schema_version": self.schema_version,
            "project_name": self.project_name,
            "root": str(self.root),
            "source_path": str(self.source_path),
            "demo_mode": self.demo_mode,
            "directories": self.directories.to_dict(),
            "limits": self.limits.to_dict(),
            "required_authors": list(self.required_authors),
            "license": self.license,
            "allowed_sigma_statuses": sorted(str(s) for s in self.allowed_sigma_statuses),
            "blocked_sigma_statuses": sorted(str(s) for s in self.blocked_sigma_statuses),
            "allowed_maturity": sorted(str(m) for m in self.allowed_maturity),
            "synthetic_hosts": list(self.synthetic_hosts),
            "synthetic_users": list(self.synthetic_users),
            "synthetic_banner": self.synthetic_banner,
        }


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"{label}: configuration file not found at {path}")
    try:
        text = safe_read_text(path, max_bytes=CONFIG_MAX_BYTES)
    except Exception as exc:
        raise ConfigError(f"{label}: cannot read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{label}: invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{label}: root of {path} must be an object")
    return data


def _require_mapping(data: Mapping[str, Any], key: str, label: str) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{label}: '{key}' must be an object, got {type(value).__name__}")
    return dict(value)


def _require_str_list(data: Mapping[str, Any], key: str, label: str) -> tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ConfigError(f"{label}: '{key}' must be an array of strings")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError(f"{label}: '{key}[{index}]' must be a string")
        result.append(item)
    return tuple(result)


def validate_limits(values: Mapping[str, Any], *, label: str = "limits") -> Limits:
    """Validate a raw ``limits`` mapping and build a :class:`Limits`.

    Each integer limit must be an ``int`` (``bool`` is rejected, since Python
    treats it as an integer) inside the range declared in :data:`LIMIT_BOUNDS`.
    Unknown keys are rejected so a typo cannot silently leave a default in place.

    Raises:
        ConfigError: on any missing, mistyped, out-of-range, or unknown key.
    """
    known = set(LIMIT_BOUNDS) | set(BOOLEAN_LIMITS)
    unknown = sorted(set(values) - known)
    if unknown:
        raise ConfigError(f"{label}: unknown limit keys: {', '.join(unknown)}")

    resolved: dict[str, Any] = {}
    for key, (minimum, maximum) in LIMIT_BOUNDS.items():
        if key not in values:
            raise ConfigError(f"{label}: missing required limit '{key}'")
        raw = values[key]
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ConfigError(
                f"{label}.{key}: must be an integer, got {type(raw).__name__} ({raw!r})"
            )
        if not minimum <= raw <= maximum:
            raise ConfigError(
                f"{label}.{key}: value {raw} outside accepted range [{minimum}, {maximum}]"
            )
        resolved[key] = raw

    for key in BOOLEAN_LIMITS:
        if key not in values:
            raise ConfigError(f"{label}: missing required limit '{key}'")
        raw = values[key]
        if not isinstance(raw, bool):
            raise ConfigError(f"{label}.{key}: must be a boolean, got {type(raw).__name__}")
        resolved[key] = raw

    if resolved["allow_symlinks"]:
        raise ConfigError(
            f"{label}.allow_symlinks: symlink following is not permitted in this project"
        )
    return Limits(**resolved)


def _validate_directories(values: Mapping[str, Any], label: str) -> ProjectDirectories:
    missing = [key for key in REQUIRED_PATH_KEYS if key not in values]
    if missing:
        raise ConfigError(f"{label}.paths: missing required keys: {', '.join(missing)}")
    resolved: dict[str, str] = {}
    for key in REQUIRED_PATH_KEYS:
        raw = values[key]
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError(f"{label}.paths.{key}: must be a non-empty string")
        normalised = raw.strip().replace("\\", "/")
        if normalised.startswith("/") or ".." in normalised.split("/"):
            raise ConfigError(
                f"{label}.paths.{key}: must be a relative path inside the project, got {raw!r}"
            )
        resolved[key] = normalised
    return ProjectDirectories(**resolved)


def load_config(
    root: Path | str | None = None,
    *,
    profile: str = DEFAULT_PROFILE,
) -> LabConfig:
    """Load and validate ``config/<profile>.config.json``.

    Args:
        root: Project root. Discovered from the working directory when omitted.
        profile: Configuration profile name, ``default`` or ``demo``.

    Returns:
        A validated :class:`LabConfig`.

    Raises:
        ConfigError: if the file is missing, malformed, or violates a bound.
    """
    if not profile or "/" in profile or "\\" in profile or ".." in profile:
        raise ConfigError(f"invalid configuration profile name: {profile!r}")

    project_root = Path(root) if root is not None else find_project_root()
    project_root = project_root.absolute()
    label = f"config/{profile}.config.json"
    source = safe_resolve(project_root, f"{CONFIG_DIRECTORY}/{profile}.config.json")
    data = _read_json(source, label=label)

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version:
        raise ConfigError(f"{label}: 'schema_version' must be a non-empty string")

    project_name = data.get("project_name")
    if not isinstance(project_name, str) or not project_name:
        raise ConfigError(f"{label}: 'project_name' must be a non-empty string")

    directories = _validate_directories(_require_mapping(data, "paths", label), label)
    limits = validate_limits(_require_mapping(data, "limits", label), label=f"{label}.limits")

    authors_block = _require_mapping(data, "authors", label)
    required_authors = _require_str_list(authors_block, "required", f"{label}.authors")
    if not required_authors:
        raise ConfigError(f"{label}.authors.required: at least one author must be declared")

    license_value = data.get("license", PROJECT_LICENSE)
    if not isinstance(license_value, str) or not license_value:
        raise ConfigError(f"{label}: 'license' must be a non-empty string")

    try:
        allowed_statuses = parse_status_set(
            _require_str_list(data, "allowed_sigma_statuses", label)
        )
        blocked_statuses = parse_status_set(
            _require_str_list(data, "blocked_sigma_statuses_main_catalog", label)
        )
    except UnknownStatusError as exc:
        raise ConfigError(f"{label}: {exc}") from exc

    if not allowed_statuses:
        raise ConfigError(f"{label}.allowed_sigma_statuses: must not be empty")
    overlap = allowed_statuses & blocked_statuses
    if overlap:
        names = ", ".join(sorted(str(status) for status in overlap))
        raise ConfigError(f"{label}: statuses both allowed and blocked: {names}")

    try:
        allowed_maturity = parse_maturity_set(_require_str_list(data, "allowed_maturity", label))
    except UnknownMaturityError as exc:
        raise ConfigError(f"{label}: {exc}") from exc
    if not allowed_maturity:
        raise ConfigError(f"{label}.allowed_maturity: must not be empty")

    banner = data.get("synthetic_banner", SYNTHETIC_DATA_BANNER)
    if not isinstance(banner, str) or not banner:
        raise ConfigError(f"{label}: 'synthetic_banner' must be a non-empty string")

    demo_mode = data.get("demo_mode", False)
    if not isinstance(demo_mode, bool):
        raise ConfigError(f"{label}: 'demo_mode' must be a boolean")

    return LabConfig(
        root=project_root,
        source_path=source,
        profile=profile,
        schema_version=schema_version,
        project_name=project_name,
        directories=directories,
        limits=limits,
        required_authors=required_authors,
        license=license_value,
        allowed_sigma_statuses=allowed_statuses,
        blocked_sigma_statuses=blocked_statuses,
        allowed_maturity=allowed_maturity,
        synthetic_hosts=_require_str_list(data, "synthetic_hosts", label),
        synthetic_users=_require_str_list(data, "synthetic_users", label),
        synthetic_banner=banner,
        demo_mode=demo_mode,
        raw=data,
    )


@dataclass(frozen=True)
class EvaluatorProfile:
    """The documented matcher and correlation subset from ``evaluator-profile.json``."""

    name: str
    purpose: str
    supported_modifiers: frozenset[str]
    supported_condition_ops: frozenset[str]
    unsupported: frozenset[str]
    default_case_sensitive: bool
    max_regex_length: int
    reject_catastrophic_patterns: bool
    correlation_types: frozenset[str]
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "supported_modifiers": sorted(self.supported_modifiers),
            "supported_condition_ops": sorted(self.supported_condition_ops),
            "unsupported": sorted(self.unsupported),
            "default_case_sensitive": self.default_case_sensitive,
            "max_regex_length": self.max_regex_length,
            "reject_catastrophic_patterns": self.reject_catastrophic_patterns,
            "correlation_types": sorted(self.correlation_types),
        }


DEFAULT_EVALUATOR_PROFILE: Final[EvaluatorProfile] = EvaluatorProfile(
    name="sdel-lab-matcher-v1",
    purpose="Deterministic behavioral unit testing only. Not a SIEM backend substitute.",
    supported_modifiers=frozenset(
        {"contains", "startswith", "endswith", "re", "cidr", "exists", "all", "cased"}
    ),
    supported_condition_ops=frozenset(
        {
            "and",
            "or",
            "not",
            "parentheses",
            "named_selection",
            "1_of_prefix_star",
            "all_of_prefix_star",
        }
    ),
    unsupported=frozenset(
        {
            "unknown_modifiers",
            "aggregations",
            "backend_custom_fields",
            "arbitrary_expressions",
            "near",
            "gt",
            "gte",
            "lt",
            "lte",
            "expand",
        }
    ),
    default_case_sensitive=False,
    max_regex_length=256,
    reject_catastrophic_patterns=True,
    correlation_types=frozenset({"event_count", "value_count", "temporal", "temporal_ordered"}),
)


def load_evaluator_profile(config: LabConfig) -> EvaluatorProfile:
    """Load ``config/evaluator-profile.json``, falling back to the built-in default.

    The built-in default is not a silent fallback for a broken file: a malformed
    profile raises. It only applies when the file is absent, so the matcher stays
    usable in a minimal checkout.
    """
    label = "config/evaluator-profile.json"
    path = safe_resolve(config.root, f"{CONFIG_DIRECTORY}/evaluator-profile.json")
    if not path.is_file():
        return DEFAULT_EVALUATOR_PROFILE

    data = _read_json(path, label=label)
    case_handling = _require_mapping(data, "case_handling", label)
    default_case = case_handling.get("default", "case_insensitive")
    if default_case not in {"case_insensitive", "case_sensitive"}:
        raise ConfigError(
            f"{label}.case_handling.default: must be 'case_insensitive' or 'case_sensitive'"
        )

    regex_block = _require_mapping(data, "regex", label)
    max_regex_length = regex_block.get("max_length", config.limits.max_regex_length)
    if isinstance(max_regex_length, bool) or not isinstance(max_regex_length, int):
        raise ConfigError(f"{label}.regex.max_length: must be an integer")
    minimum, maximum = LIMIT_BOUNDS["max_regex_length"]
    if not minimum <= max_regex_length <= maximum:
        raise ConfigError(
            f"{label}.regex.max_length: {max_regex_length} outside range [{minimum}, {maximum}]"
        )

    reject_catastrophic = regex_block.get("reject_catastrophic_patterns", True)
    if not isinstance(reject_catastrophic, bool):
        raise ConfigError(f"{label}.regex.reject_catastrophic_patterns: must be a boolean")

    name = data.get("name", DEFAULT_EVALUATOR_PROFILE.name)
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{label}: 'name' must be a non-empty string")

    return EvaluatorProfile(
        name=name,
        purpose=str(data.get("purpose", DEFAULT_EVALUATOR_PROFILE.purpose)),
        supported_modifiers=frozenset(_require_str_list(data, "supported_modifiers", label))
        or DEFAULT_EVALUATOR_PROFILE.supported_modifiers,
        supported_condition_ops=frozenset(_require_str_list(data, "supported_condition_ops", label))
        or DEFAULT_EVALUATOR_PROFILE.supported_condition_ops,
        unsupported=frozenset(_require_str_list(data, "unsupported", label)),
        default_case_sensitive=default_case == "case_sensitive",
        max_regex_length=max_regex_length,
        reject_catastrophic_patterns=reject_catastrophic,
        correlation_types=frozenset(_require_str_list(data, "correlation_supported_types", label))
        or DEFAULT_EVALUATOR_PROFILE.correlation_types,
        raw=data,
    )


@dataclass(frozen=True)
class BackendConfig:
    """One conversion backend declared in ``config/conversion-backends.json``."""

    key: str
    enabled: bool
    package: str
    version: str
    backend_class: str
    dialect: str
    demonstration_banner: str
    pipeline: str | None = None

    @property
    def module_path(self) -> str:
        """Return the importable module part of ``backend_class``."""
        return self.backend_class.rsplit(".", 1)[0]

    @property
    def class_name(self) -> str:
        """Return the class name part of ``backend_class``."""
        return self.backend_class.rsplit(".", 1)[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "enabled": self.enabled,
            "package": self.package,
            "version": self.version,
            "backend_class": self.backend_class,
            "dialect": self.dialect,
            "demonstration_banner": self.demonstration_banner,
            "pipeline": self.pipeline,
        }


@dataclass(frozen=True)
class ConversionConfig:
    """Parsed ``config/conversion-backends.json``."""

    backends: tuple[BackendConfig, ...] = ()
    correlation_supported: bool = False
    notes: str = ""

    def enabled_backends(self) -> tuple[BackendConfig, ...]:
        return tuple(backend for backend in self.backends if backend.enabled)

    def get(self, key: str) -> BackendConfig | None:
        for backend in self.backends:
            if backend.key == key:
                return backend
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "backends": [backend.to_dict() for backend in self.backends],
            "correlation_supported": self.correlation_supported,
            "notes": self.notes,
        }


def load_conversion_config(config: LabConfig) -> ConversionConfig:
    """Load ``config/conversion-backends.json``.

    Returns an empty configuration when the file is absent, which the conversion
    subsystem reports as "no backends configured" rather than treating as success.
    """
    label = "config/conversion-backends.json"
    path = safe_resolve(config.root, f"{CONFIG_DIRECTORY}/conversion-backends.json")
    if not path.is_file():
        return ConversionConfig()

    data = _read_json(path, label=label)
    backends_block = _require_mapping(data, "backends", label)
    backends: list[BackendConfig] = []
    for key in sorted(backends_block):
        entry = backends_block[key]
        if not isinstance(entry, Mapping):
            raise ConfigError(f"{label}.backends.{key}: must be an object")
        backend_class = entry.get("backend_class")
        if not isinstance(backend_class, str) or "." not in backend_class:
            raise ConfigError(f"{label}.backends.{key}.backend_class: must be a dotted import path")
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{label}.backends.{key}.enabled: must be a boolean")
        pipeline = entry.get("pipeline")
        if pipeline is not None and not isinstance(pipeline, str):
            raise ConfigError(f"{label}.backends.{key}.pipeline: must be a string or null")
        backends.append(
            BackendConfig(
                key=key,
                enabled=enabled,
                package=str(entry.get("package", "")),
                version=str(entry.get("version", "")),
                backend_class=backend_class,
                dialect=str(entry.get("dialect", "")),
                demonstration_banner=str(entry.get("demonstration_banner", "")),
                pipeline=pipeline,
            )
        )

    correlation_block = _require_mapping(data, "correlation_conversion", label)
    supported = correlation_block.get("supported_in_v1", False)
    if not isinstance(supported, bool):
        raise ConfigError(f"{label}.correlation_conversion.supported_in_v1: must be a boolean")

    return ConversionConfig(
        backends=tuple(backends),
        correlation_supported=supported,
        notes=str(correlation_block.get("notes", "")),
    )


def load_upstream_versions(config: LabConfig) -> dict[str, Any]:
    """Load ``config/upstream-versions.json``, or an empty mapping if absent."""
    path = safe_resolve(config.root, f"{CONFIG_DIRECTORY}/upstream-versions.json")
    if not path.is_file():
        return {}
    return _read_json(path, label="config/upstream-versions.json")


def read_config_json(config: LabConfig, filename: str) -> dict[str, Any]:
    """Read an arbitrary JSON file from the project ``config`` directory.

    Raises:
        ConfigError: if the name is not a plain filename or the file is invalid.
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        raise ConfigError(f"invalid config filename: {filename!r}")
    path = safe_resolve(config.root, f"{CONFIG_DIRECTORY}/{filename}")
    return _read_json(path, label=f"{CONFIG_DIRECTORY}/{filename}")


__all__ = [
    "BOOLEAN_LIMITS",
    "CONFIG_DIRECTORY",
    "DEFAULT_EVALUATOR_PROFILE",
    "DEFAULT_PROFILE",
    "LIMIT_BOUNDS",
    "REQUIRED_PATH_KEYS",
    "BackendConfig",
    "ConversionConfig",
    "EvaluatorProfile",
    "LabConfig",
    "Limits",
    "ProjectDirectories",
    "load_config",
    "load_conversion_config",
    "load_evaluator_profile",
    "load_upstream_versions",
    "read_config_json",
    "validate_limits",
]
