"""Exception hierarchy for the laboratory.

Every failure raised on purpose by this package derives from :class:`SdelError`,
so callers can distinguish deliberate refusals from genuine bugs.
"""

from __future__ import annotations


class SdelError(Exception):
    """Base class for all laboratory errors."""


class ConfigError(SdelError):
    """Configuration file missing, malformed, or outside accepted bounds."""


class PathSafetyError(SdelError):
    """A path escaped the project root, was a symlink, or was too long."""


class YamlSafetyError(SdelError):
    """YAML input violated a safety limit or used a forbidden construct."""


class RuleLoadError(SdelError):
    """A Sigma rule document could not be loaded or parsed."""


class CatalogError(SdelError):
    """Rule catalog inconsistency such as a duplicate identifier."""


class ConditionSyntaxError(SdelError):
    """A Sigma condition string is syntactically invalid."""


class UnsupportedConditionError(SdelError):
    """A Sigma condition uses a construct outside the documented lab subset."""


class MatcherError(SdelError):
    """Base class for matcher failures."""


class UnsupportedModifierError(MatcherError):
    """A field modifier is outside the documented lab subset."""


class RegexSafetyError(MatcherError):
    """A regular expression was too long or structurally dangerous."""


class CorrelationError(SdelError):
    """A correlation rule is malformed or uses an unsupported type."""


class FixtureError(SdelError):
    """A fixture file or manifest is malformed or exceeds safety limits."""


class MetadataError(SdelError):
    """A sidecar metadata document is malformed or inconsistent."""


class AttackCatalogError(SdelError):
    """The vendored ATT&CK catalog is missing or malformed."""


class TelemetryError(SdelError):
    """The telemetry catalog is missing or malformed."""


class ConversionError(SdelError):
    """A backend conversion could not be attempted or completed."""


class ReportError(SdelError):
    """A report could not be rendered or written."""


__all__ = [
    "AttackCatalogError",
    "CatalogError",
    "ConditionSyntaxError",
    "ConfigError",
    "ConversionError",
    "CorrelationError",
    "FixtureError",
    "MatcherError",
    "MetadataError",
    "PathSafetyError",
    "RegexSafetyError",
    "ReportError",
    "RuleLoadError",
    "SdelError",
    "TelemetryError",
    "UnsupportedConditionError",
    "UnsupportedModifierError",
    "YamlSafetyError",
]
